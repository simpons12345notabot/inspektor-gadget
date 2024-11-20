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

package api

import (
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"
)

//go:wasmimport env newPerfReader
func newPerfReader(mapHandle uint32, size uint32, isOverwritable uint32) uint32

//go:wasmimport env perfReaderPause
func perfReaderPause(perfMapHandle uint32) uint32

//go:wasmimport env perfReaderResume
func perfReaderResume(perfMapHandle uint32) uint32

//go:wasmimport env perfReaderSetDeadline
func perfReaderSetDeadline(perfMapHandle uint32, nsec uint64) uint32

//go:wasmimport env perfReaderRead
func perfReaderRead(perfMapHandle uint32, addrBufPtr uint32) uint32

//go:wasmimport env perfReaderClose
func perfReaderClose(perfMapHandle uint32) uint32

type PerfReader uint32

func NewPerfReader(m Map, size uint32, isOverwritable bool) (PerfReader, error) {
	var isOverwritableUint32 uint32
	if isOverwritable {
		isOverwritableUint32 = 1
	}

	ret := newPerfReader(uint32(m), size, isOverwritableUint32)
	if ret == 0 {
		return 0, errors.New("creating perf reader")
	}

	return PerfReader(ret), nil
}

func (p PerfReader) Pause() error {
	ret := perfReaderPause(uint32(p))
	if ret != 0 {
		return errors.New("pausing perf reader")
	}

	return nil
}

func (p PerfReader) Resume() error {
	ret := perfReaderResume(uint32(p))
	if ret != 0 {
		return errors.New("resuming perf reader")
	}

	return nil
}

func (p PerfReader) SetDeadline(time time.Time) error {
	ret := perfReaderSetDeadline(uint32(p), uint64(time.UnixNano()))
	if ret != 0 {
		return errors.New("setting perf reader deadline to now")
	}

	return nil
}

func (p PerfReader) Read() ([]byte, error) {
	var buf bufPtr

	ret := perfReaderRead(uint32(p), uint32(uintptr(unsafe.Pointer(&buf))))
	switch ret {
	case 0:
		return buf.bytes(), nil
	case 1:
		return nil, errors.New("reading perf reader record")
	case 2:
		return nil, os.ErrDeadlineExceeded
	default:
		return nil, fmt.Errorf("bad return value: expected 0, 1 or 2, got %d", ret)
	}
}

func (p PerfReader) Close() error {
	ret := perfReaderClose(uint32(p))
	if ret != 0 {
		return errors.New("closing perf reader")
	}

	return nil
}
