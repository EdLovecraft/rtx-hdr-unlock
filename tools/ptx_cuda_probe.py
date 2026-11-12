# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 EdLovecraft
"""Isolated CUDA lab for the PTX shipped in nvAIHDRx.dll.

Loads a local PTX copy; does not alter NVIDIA files, profiles, or other processes.
Parameters are experimental unless verified against the host implementation.
"""
import argparse
import ctypes as c
import json
from pathlib import Path
import struct

import numpy as np


class Array3D(c.Structure):
    _fields_ = [("width", c.c_size_t), ("height", c.c_size_t), ("depth", c.c_size_t),
                ("format", c.c_uint), ("channels", c.c_uint), ("flags", c.c_uint)]


class ResourceUnion(c.Union):
    _fields_ = [("array", c.c_void_p), ("reserved", c.c_int * 32)]


class Resource(c.Structure):
    _fields_ = [("kind", c.c_uint), ("res", ResourceUnion), ("flags", c.c_uint)]


class Texture(c.Structure):
    _fields_ = [("address", c.c_uint * 3), ("filter", c.c_uint), ("flags", c.c_uint),
                ("anisotropy", c.c_uint), ("mip_filter", c.c_uint), ("mip_bias", c.c_float),
                ("mip_min", c.c_float), ("mip_max", c.c_float), ("border", c.c_float * 4),
                ("reserved", c.c_int * 12)]


class Copy2D(c.Structure):
    _fields_ = [("sx", c.c_size_t), ("sy", c.c_size_t), ("skind", c.c_uint),
                ("shost", c.c_void_p), ("sdevice", c.c_ulonglong), ("sarray", c.c_void_p),
                ("spitch", c.c_size_t), ("dx", c.c_size_t), ("dy", c.c_size_t),
                ("dkind", c.c_uint), ("dhost", c.c_void_p), ("ddevice", c.c_ulonglong),
                ("darray", c.c_void_p), ("dpitch", c.c_size_t), ("width", c.c_size_t),
                ("height", c.c_size_t)]


class Lab:
    def __init__(self, width=257, height=1):
        self.cu = c.WinDLL("nvcuda.dll")
        self.width, self.height = width, height
        self.ctx = c.c_void_p()
        self.call("cuInit", 0)
        self.call("cuCtxCreate_v2", c.byref(self.ctx), 0, 0)
        self.arrays = []
        self.textures = []
        self.surfaces = []
        self.modules = []
        self.input, self.tex = self.array(texture=True)
        self.output, self.surf = self.array(texture=False)
        self.pov = c.c_ulonglong()
        self.call("cuMemAlloc_v2", c.byref(self.pov), c.c_size_t(4))
        zero = c.c_float(0)
        self.call("cuMemcpyHtoD_v2", self.pov, c.byref(zero), c.c_size_t(4))

    def call(self, name, *args):
        result = getattr(self.cu, name)(*args)
        if result:
            msg = c.c_char_p()
            self.cu.cuGetErrorString(result, c.byref(msg))
            raise RuntimeError(f"{name}: {result} ({msg.value!r})")

    def array(self, texture):
        arr = c.c_void_p()
        desc = Array3D(self.width, self.height, 0, 0x20, 4, 2)
        self.call("cuArray3DCreate_v2", c.byref(arr), c.byref(desc))
        self.arrays.append(arr)
        res = Resource()
        res.res.array = arr
        handle = c.c_ulonglong()
        if texture:
            tex = Texture()
            tex.address[:] = [1, 1, 1]
            tex.anisotropy = 1
            self.call("cuTexObjectCreate", c.byref(handle), c.byref(res), c.byref(tex), None)
            self.textures.append(handle)
        else:
            self.call("cuSurfObjectCreate", c.byref(handle), c.byref(res))
            self.surfaces.append(handle)
        return arr, handle.value

    def upload(self, data):
        data = np.ascontiguousarray(data, dtype=np.float32)
        assert data.shape == (self.height, self.width, 4)
        cp = Copy2D()
        cp.skind, cp.shost, cp.spitch = 1, data.ctypes.data, self.width * 16
        cp.dkind, cp.darray = 3, self.input.value
        cp.width, cp.height = self.width * 16, self.height
        self.call("cuMemcpy2D_v2", c.byref(cp))

    def download(self):
        data = np.empty((self.height, self.width, 4), dtype=np.float32)
        cp = Copy2D()
        cp.skind, cp.sarray = 3, self.output.value
        cp.dkind, cp.dhost, cp.dpitch = 1, data.ctypes.data, self.width * 16
        cp.width, cp.height = self.width * 16, self.height
        self.call("cuMemcpy2D_v2", c.byref(cp))
        return data

    def load(self, ptx):
        """Load PTX text or a cubin byte string into this owned CUDA context."""
        module = c.c_void_p()
        log = c.create_string_buffer(16000)
        options = (c.c_int * 2)(5, 6)
        values = (c.c_void_p * 2)(c.cast(log, c.c_void_p), c.c_void_p(len(log)))
        try:
            image = ptx.encode() if isinstance(ptx, str) else ptx
            self.call("cuModuleLoadDataEx", c.byref(module), image, 2, options, values)
        except RuntimeError:
            print(log.value.decode(errors="replace"))
            raise
        self.modules.append(module)
        func = c.c_void_p()
        self.call("cuModuleGetFunction", c.byref(func), module, b"truehdr_drtm")
        return func

    def params(self, peak=1260, white=200, path=1, flag42=0, flag43=0, pq=False,
               gamma=2.2, contrast=1.0, contrast2=1.0, saturation=1.0):
        p = bytearray(104)
        struct.pack_into("<4I", p, 0, self.width, self.height, self.width, self.height)
        struct.pack_into("<6f", p, 16, gamma, 1.0, contrast, contrast2, saturation, white)
        struct.pack_into("<5B", p, 40, 0, 0, flag42, flag43, int(pq))
        struct.pack_into("<fIB3xIQ", p, 56, peak, 0, 1, path, self.pov.value)
        assert self.tex < 2**32 and self.surf < 2**32, (self.tex, self.surf)
        struct.pack_into("<4I", p, 80, self.tex, self.tex, self.tex, self.surf)
        return p

    def run(self, func, params):
        p = c.create_string_buffer(bytes(params))
        argv = (c.c_void_p * 1)(c.cast(p, c.c_void_p))
        self.call("cuLaunchKernel", func, (self.width + 31)//32, self.height, 1,
                  32, 1, 1, 0, None, argv, None)
        self.call("cuCtxSynchronize")
        return self.download()

    def close(self):
        for m in self.modules:
            self.call("cuModuleUnload", m)
        for h in self.textures:
            self.call("cuTexObjectDestroy", h)
        for h in self.surfaces:
            self.call("cuSurfObjectDestroy", h)
        for a in self.arrays:
            self.call("cuArrayDestroy", a)
        self.call("cuMemFree_v2", self.pov)
        self.call("cuCtxDestroy_v2", self.ctx)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ptx", default="analysis/ptx_module_4.ptx")
    ap.add_argument("--output", default="analysis/ptx_cuda_probe.json")
    args = ap.parse_args()
    lab = Lab()
    print("handles", hex(lab.tex), hex(lab.surf))
    try:
        func = lab.load(Path(args.ptx).read_text())
        ramp = np.zeros((1, lab.width, 4), dtype=np.float32)
        ramp[0, :, :3] = np.linspace(0, 1, lab.width)[:, None]
        lab.upload(ramp)
        records = []
        for path in [0, 1, 2, 3]:
            for f42 in [0, 1]:
                for peak in [700, 1000, 1260, 2000]:
                    out = lab.run(func, lab.params(peak=peak, path=path, flag42=f42))
                    nits = out[0, :, :3] * 80
                    r = dict(path=path, flag42=f42, peak=peak, max_rgb_nits=nits.max(axis=0).tolist(),
                             ramp_nits=nits[:, 0].tolist(), nonfinite=int((~np.isfinite(out)).sum()))
                    records.append(r)
                    print({k:v for k,v in r.items() if k!="ramp_nits"})
        Path(args.output).write_text(json.dumps(records, indent=2))
    finally:
        lab.close()


if __name__ == "__main__":
    main()
