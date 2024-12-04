// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
	tracelooptypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// These consts must match the content of program.bpf.c.
const (
	useNullByteLength        uint64 = 0x0fffffffffffffff
	useRetAsParamLength      uint64 = 0x0ffffffffffffffe
	useArgIndexAsParamLength uint64 = 0x0ffffffffffffff0
	paramProbeAtExitMask     uint64 = 0xf000000000000000

	syscallEventTypeEnter uint8 = 0
	syscallEventTypeExit  uint8 = 1

	syscallArgs uint8 = 6
)

type containerRingReader struct {
	innerBuffer api.Map
	perfReader  api.PerfReader
	mntnsID     uint64
}

type tracelooper struct {
	mapOfPerfBuffers api.Map

	// key:   containerID
	// value: *containerRingReader
	readers sync.Map
}

var t tracelooper

type traceloopSyscallEventContT struct {
	Param              [128]uint8
	MonotonicTimestamp uint64
	Length             uint64
	Index              uint8
	Failed             uint8
	_                  [6]byte
}

type traceloopSyscallEventT struct {
	Args               [6]uint64
	MonotonicTimestamp uint64
	BootTimestamp      uint64
	Pid                uint32
	Cpu                uint16
	Id                 uint16
	Comm               [16]uint8
	ContNr             uint8
	Typ                uint8
	_                  [6]byte
}

type syscallEvent struct {
	bootTimestamp      uint64
	monotonicTimestamp uint64
	typ                uint8
	contNr             uint8
	cpu                uint16
	id                 uint16
	pid                uint32
	comm               string
	args               []uint64
	mountNsID          uint64
	retval             uint64
}

type syscallEventContinued struct {
	monotonicTimestamp uint64
	index              uint8
	param              string
}

func (t *tracelooper) attach(containerID uint64, mntnsID uint64) error {
	perfBufferName := fmt.Sprintf("perf_buffer_%d", mntnsID)

	// 1. Create inner Map as perf buffer.
	// Keep the spec in sync with program.bpf.c.
	innerBuffer, err := api.NewMap(api.MapSpec{
		Name:       perfBufferName,
		Type:       api.PerfEventArray,
		KeySize:    uint32(4),
		ValueSize:  uint32(4),
	})
	if err != nil {
		api.Errorf("creating map %s", fmt.Sprintf("perf_buffer_%d", mntnsID))
	}

	// 2. Use this inner Map to create the perf reader.
	perfReader, err := api.NewPerfReader(innerBuffer, uint32(64*os.Getpagesize()), true)
	if err != nil {
		innerBuffer.Close()

		return fmt.Errorf("creating perf ring buffer: %w", err)
	}

	// 3. Add the inner map's file descriptor to outer map.
	err = t.mapOfPerfBuffers.Update(mntnsID, innerBuffer.FD(), api.UpdateNoExist)
	if err != nil {
		innerBuffer.Close()
		perfReader.Close()

		return fmt.Errorf("adding perf buffer to map with mntnsID %d: %w", mntnsID, err)
	}

	t.readers.Store(containerID, &containerRingReader{
		innerBuffer: innerBuffer,
		perfReader:  perfReader,
		mntnsID:     mntnsID,
	})

	return nil
}

func (t *tracelooper) detach(reader *containerRingReader) error {
	// We call this from gadgetStop() where the map was already closed, let's
	// comment
// 	err := t.mapOfPerfBuffers.Delete(reader.mntnsID)
// 	if err != nil {
// 		return fmt.Errorf("removing perf buffer from map with mntnsID %d: %v", reader.mntnsID, err)
// 	}

	err := reader.innerBuffer.Close()
	if err != nil {
		return fmt.Errorf("closing map %s: %v", fmt.Sprintf("perf_buffer_%d", reader.mntnsID), err)
	}

	return nil
}

func fromCString(in []byte) string {
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			return string(in[:i])
		}
	}
	return string(in)
}

func fromCStringN(in []byte, length int) string {
	l := len(in)
	if length < l {
		l = length
	}

	for i := 0; i < l; i++ {
		if in[i] == 0 {
			return string(in[:i])
		}
	}
	return string(in[:l])
}

func wallTimeFromBootTime(ts uint64) eventtypes.Time {
	if ts == 0 {
		return eventtypes.Time(time.Now().UnixNano())
	}
	return eventtypes.Time(time.Unix(0, int64(ts)).Add(0/*timeDiff*/).UnixNano())
}

func timestampFromEvent(event *syscallEvent) eventtypes.Time {
	return wallTimeFromBootTime(event.bootTimestamp)
}

// Copied/pasted/adapted from kernel macro round_up:
// https://elixir.bootlin.com/linux/v6.0/source/include/linux/math.h#L25
func roundUp(x, y uintptr) uintptr {
	return ((x - 1) | (y - 1)) + 1
}

// The kernel aligns size of perf event with the following snippet:
// void perf_prepare_sample(...)
//
//	{
//		//...
//		size = round_up(sum + sizeof(u32), sizeof(u64));
//		raw->size = size - sizeof(u32);
//		frag->pad = raw->size - sum;
//		// ...
//	}
//
// (https://elixir.bootlin.com/linux/v6.0/source/kernel/events/core.c#L7353)
// In the case of our structure of interest (i.e. struct_syscall_event_t and
// struct_syscall_event_cont_t), their size will be increased by 4, here is
// an example for struct_syscall_event_t which size is 88:
// size = round_up(sum + sizeof(u32), sizeof(u64))
//
//	= round_up(88 + 4, 8)
//	= round_up(92, 8)
//	= 96
//
// raw->size = size - sizeof(u32)
//
//	= 96 - 4
//	= 92
//
// So, 4 bytes will be added as padding at the end of the event and the size we
// will read getting perfEventSample will be 92 instead of 88.
func alignSize(structSize uintptr) uintptr {
	var ret uintptr
	var foo uint64
	var bar uint32

	ret = roundUp(structSize+unsafe.Sizeof(bar), unsafe.Sizeof(foo))
	ret = ret - unsafe.Sizeof(bar)

	return ret
}

// Convert a return value to corresponding error number if meaningful.
// See man syscalls:
// Note:
// system calls indicate a failure by returning a negative error
// number to the caller on architectures without a separate error
// register/flag, as noted in syscall(2); when this happens, the
// wrapper function negates the returned error number (to make it
// positive), copies it to errno, and returns -1 to the caller of
// the wrapper.
func retToStr(ret uint64) string {
	errNo := int64(ret)
	if errNo >= -4095 && errNo <= -1 {
		return fmt.Sprintf("-1 (%s)", syscall.Errno(-errNo).Error())
	}
	return fmt.Sprintf("%d", ret)
}

func (t *tracelooper) read(reader *containerRingReader) ([]*tracelooptypes.Event, error) {
	syscallContinuedEventsMap := make(map[uint64][]*syscallEventContinued)
	syscallEnterEventsMap := make(map[uint64][]*syscallEvent)
	syscallExitEventsMap := make(map[uint64][]*syscallEvent)
	events := make([]*tracelooptypes.Event, 0)

	err := reader.perfReader.Pause()
	if err != nil {
		return nil, err
	}

	reader.perfReader.SetDeadline(time.Now())

	records := make([][]byte, 0)
	for {
		record, err := reader.perfReader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			} else {
				return nil, err
			}
		}
		records = append(records, record)
	}

	err = reader.perfReader.Resume()
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		size := len(record)

		var sysEvent *traceloopSyscallEventT
		var sysEventCont *traceloopSyscallEventContT

		switch uintptr(size) {
		case alignSize(unsafe.Sizeof(*sysEvent)):
			sysEvent = (*traceloopSyscallEventT)(unsafe.Pointer(&record[0]))

			event := &syscallEvent{
				bootTimestamp:      sysEvent.BootTimestamp,
				monotonicTimestamp: sysEvent.MonotonicTimestamp,
				typ:                sysEvent.Typ,
				contNr:             sysEvent.ContNr,
				cpu:                sysEvent.Cpu,
				id:                 sysEvent.Id,
				pid:                sysEvent.Pid,
				comm:               fromCString(sysEvent.Comm[:]),
				mountNsID:          reader.mntnsID,
			}

			var typeMap *map[uint64][]*syscallEvent
			switch event.typ {
			case syscallEventTypeEnter:
				event.args = make([]uint64, syscallArgs)
				for i := uint8(0); i < syscallArgs; i++ {
					event.args[i] = sysEvent.Args[i]
				}

				typeMap = &syscallEnterEventsMap
			case syscallEventTypeExit:
				event.retval = sysEvent.Args[0]

				typeMap = &syscallExitEventsMap
			default:
				// Rather than returning an error, we skip this event.
				api.Debugf("type %d is not a valid type for syscallEvent, received data are: %v", event.typ, record)

				continue
			}

			if _, ok := (*typeMap)[event.monotonicTimestamp]; !ok {
				(*typeMap)[event.monotonicTimestamp] = make([]*syscallEvent, 0)
			}

			(*typeMap)[event.monotonicTimestamp] = append((*typeMap)[event.monotonicTimestamp], event)
		case alignSize(unsafe.Sizeof(*sysEventCont)):
			sysEventCont = (*traceloopSyscallEventContT)(unsafe.Pointer(&record[0]))

			event := &syscallEventContinued{
				monotonicTimestamp: sysEventCont.MonotonicTimestamp,
				index:              sysEventCont.Index,
			}

			if sysEventCont.Failed != 0 {
				event.param = "(Failed to dereference pointer)"
			} else if sysEventCont.Length == useNullByteLength {
				// 0 byte at [C.PARAM_LENGTH - 1] is enforced in BPF code
				event.param = fromCString(sysEventCont.Param[:])
			} else {
				event.param = fromCStringN(sysEventCont.Param[:], int(sysEventCont.Length))
			}

			// Remove all non unicode character from the string.
			event.param = strconv.Quote(event.param)

			_, ok := syscallContinuedEventsMap[event.monotonicTimestamp]
			if !ok {
				// Just create a 0 elements slice for the moment, the ContNr will be
				// checked later.
				syscallContinuedEventsMap[event.monotonicTimestamp] = make([]*syscallEventContinued, 0)
			}

			syscallContinuedEventsMap[event.monotonicTimestamp] = append(syscallContinuedEventsMap[event.monotonicTimestamp], event)
		default:
			api.Debugf("size %d does not correspond to any expected element, which are %d and %d; received data are: %v", size, unsafe.Sizeof(sysEvent), unsafe.Sizeof(sysEventCont), record)
		}
	}

	// Let's try to publish the events we gathered.
	for enterTimestamp, enterTimestampEvents := range syscallEnterEventsMap {
		for _, enterEvent := range enterTimestampEvents {
			syscallName, err := api.GetSyscallName(enterEvent.id)
			if err != nil {
				return nil, fmt.Errorf("getting syscall name: %w", err)
			}

			event := &tracelooptypes.Event{
				Event: eventtypes.Event{
					Type:      eventtypes.NORMAL,
					Timestamp: timestampFromEvent(enterEvent),
				},
				CPU:           enterEvent.cpu,
				Pid:           enterEvent.pid,
				Comm:          enterEvent.comm,
				WithMountNsID: eventtypes.WithMountNsID{MountNsID: enterEvent.mountNsID},
				Syscall:       syscallName,
			}

			syscallDeclaration, err := api.GetSyscallDeclaration(event.Syscall)
			if err != nil {
				return nil, fmt.Errorf("getting syscall definition: %w", err)
			}

			parametersNumber, err := syscallDeclaration.GetParameterCount()
			if err != nil {
				return nil, fmt.Errorf("getting syscall parameter numbers: %w", err)
			}

			event.Parameters = make([]tracelooptypes.SyscallParam, parametersNumber)
			api.Debugf("\tevent parametersNumber: %d", parametersNumber)

			for i := uint32(0); i < parametersNumber; i++ {
				paramName, err := syscallDeclaration.GetParameterName(i)
				if err != nil {
					return nil, fmt.Errorf("getting syscall parameter name: %w", err)
				}
				api.Debugf("\t\tevent paramName: %q", paramName)

				isPointer, err := syscallDeclaration.ParamIsPointer(i)
				if err != nil {
					return nil, fmt.Errorf("checking syscall parameter is a pointer: %w", err)
				}

				format := "%d"
				if isPointer {
					format = "0x%x"
				}
				paramValue := fmt.Sprintf(format, enterEvent.args[i])
				api.Debugf("\t\tevent paramValue: %q", paramValue)

				var paramContent *string

				for _, syscallContEvent := range syscallContinuedEventsMap[enterTimestamp] {
					if syscallContEvent.index == uint8(i) {
						paramContent = &syscallContEvent.param
						api.Debugf("\t\t\tevent paramContent: %q", *paramContent)

						break
					}
				}

				event.Parameters[i] = tracelooptypes.SyscallParam{
					Name:    paramName,
					Value:   paramValue,
					Content: paramContent,
				}
			}

			delete(syscallContinuedEventsMap, enterTimestamp)

			// There is no exit event for exit(), exit_group() and rt_sigreturn().
			if event.Syscall == "exit" || event.Syscall == "exit_group" || event.Syscall == "rt_sigreturn" {
				delete(syscallEnterEventsMap, enterTimestamp)

// 				if t.enricher != nil {
// 					t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
// 				}

				// As there is no exit events for these syscalls,
				// then there is no return value.
				event.Retval = "X"

				api.Debugf("%v", event)
				events = append(events, event)

				continue
			}

			exitTimestampEvents, ok := syscallExitEventsMap[enterTimestamp]
			if !ok {
				api.Debugf("no exit event for timestamp %d", enterTimestamp)

				continue
			}

			for _, exitEvent := range exitTimestampEvents {
				if enterEvent.id != exitEvent.id || enterEvent.pid != exitEvent.pid {
					continue
				}

				event.Retval = retToStr(exitEvent.retval)

				delete(syscallEnterEventsMap, enterTimestamp)
				delete(syscallExitEventsMap, enterTimestamp)

// 				if t.enricher != nil {
// 					t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
// 				}
				api.Debugf("%v", event)
				events = append(events, event)

				break
			}
		}
	}

	api.Debugf("len(events): %d; len(syscallEnterEventsMap): %d; len(syscallExitEventsMap): %d; len(syscallContinuedEventsMap): %d\n", len(events), len(syscallEnterEventsMap), len(syscallExitEventsMap), len(syscallContinuedEventsMap))

	// It is possible there are some incomplete events for two mains reasons:
	// 1. Traceloop was started in the middle of a syscall, then we will only get
	//    the exit but not the enter.
	// 2. The buffer is full and so it only remains some exit events and not the
	//    corresponding enter.
	// Rather than dropping these incomplete events, we just add them to the
	// events to be published.
	for _, enterTimestampEvents := range syscallEnterEventsMap {
		for _, enterEvent := range enterTimestampEvents {
			syscallName, err := api.GetSyscallName(enterEvent.id)
			if err != nil {
				return nil, fmt.Errorf("getting syscall name: %w", err)
			}

			incompleteEnterEvent := &tracelooptypes.Event{
				Event: eventtypes.Event{
					Type:      eventtypes.NORMAL,
					Timestamp: timestampFromEvent(enterEvent),
				},
				CPU:           enterEvent.cpu,
				Pid:           enterEvent.pid,
				Comm:          enterEvent.comm,
				WithMountNsID: eventtypes.WithMountNsID{MountNsID: enterEvent.mountNsID},
				Syscall:       syscallName,
				Retval:        "unfinished",
			}

// 			if t.enricher != nil {
// 				t.enricher.EnrichByMntNs(&incompleteEnterEvent.CommonData, incompleteEnterEvent.MountNsID)
// 			}

			events = append(events, incompleteEnterEvent)

			api.Debugf("enterEvent(%q): %v\n", syscallName, enterEvent)
		}
	}

	for _, exitTimestampEvents := range syscallExitEventsMap {
		for _, exitEvent := range exitTimestampEvents {
			syscallName, err := api.GetSyscallName(exitEvent.id)
			if err != nil {
				return nil, fmt.Errorf("getting syscall name: %w", err)
			}

			incompleteExitEvent := &tracelooptypes.Event{
				Event: eventtypes.Event{
					Type:      eventtypes.NORMAL,
					Timestamp: timestampFromEvent(exitEvent),
				},
				CPU:           exitEvent.cpu,
				Pid:           exitEvent.pid,
				Comm:          exitEvent.comm,
				WithMountNsID: eventtypes.WithMountNsID{MountNsID: exitEvent.mountNsID},
				Syscall:       syscallName,
				Retval:        retToStr(exitEvent.retval),
			}

// 			if t.enricher != nil {
// 				t.enricher.EnrichByMntNs(&incompleteExitEvent.CommonData, incompleteExitEvent.MountNsID)
// 			}

			events = append(events, incompleteExitEvent)

			api.Debugf("exitEvent(%q): %v\n", syscallName, exitEvent)
		}
	}

	// Sort all events by ascending timestamp.
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp < events[j].Timestamp
	})

	// Remove timestamps if we couldn't get reliable ones
// 	if hasBpfKtimeGetBootNs() {
// 		for i := range events {
// 			events[i].Timestamp = 0
// 		}
// 	}

	return events, nil
}

//export gadgetInit()
func gadgetInit() error {
	return nil
}

//export gadgetStart
func gadgetStart() int {
	var err error
	mapName := "map_of_perf_buffers"

	t.mapOfPerfBuffers, err = api.GetMap(mapName)
	if err != nil {
		api.Errorf("no map named %s", mapName)
		return 1
	}

	containers := api.GetContainers()
	nbContainers, err := containers.Length()
	if err != nil {
		api.Errorf("getting numbers of running containers: %v", err)
		return 1
	}

	for i := range nbContainers {
		handle, err := containers.Get(uint32(i))
		if err != nil {
			api.Errorf("getting container %d from containers: %v", i, err)
			return 1
		}

		container := api.Container(handle)

		containerID, err := container.GetCgroupID()
		if err != nil {
			api.Errorf("getting container cgroup ID: %v", err)
			return 1
		}

		mntnsID, err := container.GetMntNsID()
		if err != nil {
			api.Errorf("getting container mount namespace ID: %v", err)
			return 1
		}

		err = t.attach(containerID, mntnsID)
		if err != nil {
			api.Errorf("attaching container %v: %v", containerID, err)
			return 1
		}
	}

	return 0
}

//export gadgetStop
func gadgetStop() int {
	t.readers.Range(func(key, value any) bool {
		reader := value.(*containerRingReader)

		events, err := t.read(reader)
		if err != nil {
			api.Errorf("reading container: %v", err)
		}

		for _, event := range events {
			api.Infof("%v", event)
		}

		err = t.detach(reader)
		if err != nil {
			api.Errorf("detaching container: %v", err)
		}

		return true
	})

	return 0
}

func main() {}
