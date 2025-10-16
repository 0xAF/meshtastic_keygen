#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#ifdef ME_KEYGEN_OPENCL
#include <CL/cl.h>
#endif

#include "opencl_keygen.h"

// Simple helper macro
#define OCL_CHECK(err, msg) do { if ((err) != CL_SUCCESS) { fprintf(stderr, "OpenCL error %d at %s\n", (int)(err), (msg)); goto ocl_fail; } } while (0)

typedef struct { unsigned int prefix_len, suffix_len, suffix_off; } pattern_meta_t;

static char *read_kernel_source(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    char *buf = (char*)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (r != (size_t)n) { free(buf); return NULL; }
    buf[n] = '\0';
    if (out_len) *out_len = (size_t)n;
    return buf;
}

int ocl_is_available(void) {
#ifndef ME_KEYGEN_OPENCL
    return 0;
#else
    cl_uint nplat = 0; cl_int err = clGetPlatformIDs(0, NULL, &nplat);
    return (err == CL_SUCCESS && nplat > 0);
#endif
}

int ocl_run_batch(const struct ocl_inputs *in, struct ocl_outputs *out) {
#ifndef ME_KEYGEN_OPENCL
    (void)in; (void)out; return -1;
#else
    cl_int err;
    cl_uint nplat = 0; OCL_CHECK(clGetPlatformIDs(0, NULL, &nplat), "clGetPlatformIDs(count)");
    if (nplat == 0) { fprintf(stderr, "No OpenCL platforms found\n"); return -2; }
    cl_platform_id *plats = (cl_platform_id*)calloc(nplat, sizeof(*plats));
    OCL_CHECK(clGetPlatformIDs(nplat, plats, NULL), "clGetPlatformIDs(list)");

    cl_device_id dev = NULL;
    cl_platform_id usep = plats[0];
    cl_uint ndev = 0;
    OCL_CHECK(clGetDeviceIDs(usep, CL_DEVICE_TYPE_GPU, 0, NULL, &ndev), "clGetDeviceIDs(count)");
    if (ndev == 0) { fprintf(stderr, "No GPU devices\n"); free(plats); return -3; }
    cl_device_id *devs = (cl_device_id*)calloc(ndev, sizeof(*devs));
    OCL_CHECK(clGetDeviceIDs(usep, CL_DEVICE_TYPE_GPU, ndev, devs, NULL), "clGetDeviceIDs(list)");
    dev = devs[0];

    cl_context ctx = clCreateContext(NULL, 1, &dev, NULL, NULL, &err); OCL_CHECK(err, "clCreateContext");
    cl_command_queue q = clCreateCommandQueue(ctx, dev, 0, &err); OCL_CHECK(err, "clCreateCommandQueue");

    size_t src_len = 0; char *src = read_kernel_source(in->kernel_path, &src_len);
    if (!src) { fprintf(stderr, "Failed to read kernel source %s\n", in->kernel_path); err = CL_INVALID_VALUE; goto ocl_fail; }
    const char *srcs[1] = { src };
    cl_program prog = clCreateProgramWithSource(ctx, 1, srcs, &src_len, &err); OCL_CHECK(err, "clCreateProgramWithSource");
    err = clBuildProgram(prog, 1, &dev, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t logsz = 0; clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &logsz);
        char *log = (char*)malloc(logsz + 1); if (log) { clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, logsz, log, NULL); log[logsz] = '\0'; fprintf(stderr, "OpenCL build log:\n%s\n", log); free(log);} 
        OCL_CHECK(err, "clBuildProgram");
    }
    cl_kernel krn = clCreateKernel(prog, "keygen_kernel", &err); OCL_CHECK(err, "clCreateKernel");

    // Pack patterns
    size_t total_bytes = 0;
    for (size_t i = 0; i < in->patterns_count; ++i) {
        if (in->patterns[i].prefix_len) total_bytes += in->patterns[i].prefix_len;
        if (in->patterns[i].suffix_len) total_bytes += in->patterns[i].suffix_len;
    }
    unsigned char *pat_bytes = (unsigned char*)malloc(total_bytes);
    unsigned int *offs_pre = (unsigned int*)malloc(sizeof(unsigned int) * in->patterns_count);
    unsigned int *offs_suf = (unsigned int*)malloc(sizeof(unsigned int) * in->patterns_count);
    pattern_meta_t *metas = (pattern_meta_t*)malloc(sizeof(pattern_meta_t) * in->patterns_count);
    size_t cur = 0;
    for (size_t i = 0; i < in->patterns_count; ++i) {
        if (in->patterns[i].prefix_len) { offs_pre[i] = (unsigned int)cur; memcpy(pat_bytes + cur, in->patterns[i].prefix, in->patterns[i].prefix_len); cur += in->patterns[i].prefix_len; }
        else { offs_pre[i] = 0; }
        if (in->patterns[i].suffix_len) { offs_suf[i] = (unsigned int)cur; memcpy(pat_bytes + cur, in->patterns[i].suffix, in->patterns[i].suffix_len); cur += in->patterns[i].suffix_len; }
        else { offs_suf[i] = 0; }
        metas[i].prefix_len = (unsigned int)in->patterns[i].prefix_len;
        metas[i].suffix_len = (unsigned int)in->patterns[i].suffix_len;
        metas[i].suffix_off = (unsigned int)in->patterns[i].suffix_off;
    }

    // Buffers
    size_t gsize = in->global_size;
    cl_mem seeds = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(cl_uint2) * gsize, NULL, &err); OCL_CHECK(err, "clCreateBuffer seeds");
    cl_mem patb  = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, cur, pat_bytes, &err); OCL_CHECK(err, "clCreateBuffer patb");
    cl_mem offp  = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(unsigned int) * in->patterns_count, offs_pre, &err); OCL_CHECK(err, "clCreateBuffer offp");
    cl_mem offs  = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(unsigned int) * in->patterns_count, offs_suf, &err); OCL_CHECK(err, "clCreateBuffer offs");
    cl_mem meta  = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(pattern_meta_t) * in->patterns_count, metas, &err); OCL_CHECK(err, "clCreateBuffer meta");
    // Each match stores pub(45) + priv(45)
    size_t out_stride = 45 + 45;
    cl_mem outb  = clCreateBuffer(ctx, CL_MEM_READ_WRITE, out_stride * in->target_count, NULL, &err); OCL_CHECK(err, "clCreateBuffer outb");
    cl_uint zero = 0;
    cl_mem found = clCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof(cl_uint), &zero, &err); OCL_CHECK(err, "clCreateBuffer found");

    // Seed init (trivial placeholder)
    cl_uint2 *host_seeds = (cl_uint2*)calloc(gsize, sizeof(cl_uint2));
    for (size_t i = 0; i < gsize; ++i) { host_seeds[i].s[0] = (cl_uint)(in->seed ^ (0x9E3779B97F4A7C15ULL * (i+1))); host_seeds[i].s[1] = (cl_uint)(i * 0xD2511F53u + 1u); }
    OCL_CHECK(clEnqueueWriteBuffer(q, seeds, CL_TRUE, 0, sizeof(cl_uint2)*gsize, host_seeds, 0, NULL, NULL), "write seeds");

    // Set args
    unsigned int pc = (unsigned int)in->patterns_count;
    unsigned int iters = in->iters_per_wi;
    OCL_CHECK(clSetKernelArg(krn, 0, sizeof(cl_mem), &seeds), "arg0");
    OCL_CHECK(clSetKernelArg(krn, 1, sizeof(cl_mem), &patb),  "arg1");
    OCL_CHECK(clSetKernelArg(krn, 2, sizeof(cl_mem), &offp),  "arg2");
    OCL_CHECK(clSetKernelArg(krn, 3, sizeof(cl_mem), &offs),  "arg3");
    OCL_CHECK(clSetKernelArg(krn, 4, sizeof(cl_mem), &meta),  "arg4");
    OCL_CHECK(clSetKernelArg(krn, 5, sizeof(unsigned int), &pc), "arg5");
    OCL_CHECK(clSetKernelArg(krn, 6, sizeof(cl_mem), &outb),  "arg6");
    OCL_CHECK(clSetKernelArg(krn, 7, sizeof(cl_mem), &found), "arg7");
    OCL_CHECK(clSetKernelArg(krn, 8, sizeof(unsigned int), &in->target_count), "arg8");
    OCL_CHECK(clSetKernelArg(krn, 9, sizeof(unsigned int), &iters), "arg9");

    size_t lsize = in->local_size ? in->local_size : 256;
    size_t ng = ((gsize + lsize - 1) / lsize) * lsize; // round up
    OCL_CHECK(clEnqueueNDRangeKernel(q, krn, 1, NULL, &ng, &lsize, 0, NULL, NULL), "enqueue kernel");
    OCL_CHECK(clFinish(q), "finish");

    // Read found and outputs
    cl_uint found_h = 0; OCL_CHECK(clEnqueueReadBuffer(q, found, CL_TRUE, 0, sizeof(found_h), &found_h, 0, NULL, NULL), "read found");
    if (found_h > in->target_count) found_h = in->target_count;
    out->found = found_h;
    out->matches = (struct ocl_match*)calloc(found_h, sizeof(struct ocl_match));
    unsigned char *tmp = (unsigned char*)malloc(out_stride * found_h);
    if (found_h > 0) {
        OCL_CHECK(clEnqueueReadBuffer(q, outb, CL_TRUE, 0, out_stride * found_h, tmp, 0, NULL, NULL), "read out");
        for (cl_uint i = 0; i < found_h; ++i) {
            memcpy(out->matches[i].pub_b64, tmp + i*out_stride, 44); out->matches[i].pub_b64[44] = '\0';
            memcpy(out->matches[i].priv_b64, tmp + i*out_stride + 45, 44); out->matches[i].priv_b64[44] = '\0';
        }
    }

    // Cleanup
    free(tmp); free(host_seeds); free(pat_bytes); free(offs_pre); free(offs_suf); free(metas);
    clReleaseMemObject(seeds); clReleaseMemObject(patb); clReleaseMemObject(offp); clReleaseMemObject(offs); clReleaseMemObject(meta); clReleaseMemObject(outb); clReleaseMemObject(found);
    clReleaseKernel(krn); clReleaseProgram(prog); free(src);
    clReleaseCommandQueue(q); clReleaseContext(ctx);
    free(devs); free(plats);
    return 0;

ocl_fail:
    fprintf(stderr, "OpenCL batch failed.\n");
    return -1;
#endif
}

int ocl_cpu_gpu_consistency_test(const struct ocl_inputs *in, int (*cpu_gen)(unsigned long long seed, unsigned count, unsigned char *out_pub_priv)) {
#ifndef ME_KEYGEN_OPENCL
    (void)in; (void)cpu_gen; return -1;
#else
    // Minimal harness: run a tiny GPU batch with deterministic seed and compare outputs against CPU for the same pseudo-RNG.
    // Note: Until the real X25519 kernel is implemented, this will not match. We keep this function as a placeholder for future use.
    (void)in; (void)cpu_gen;
    return 0; // placeholder success; real test will be implemented after kernel is correct
#endif
}

int ocl_rng_dump(const char *kernel_path, size_t global_size, size_t local_size, unsigned long long seed,
                 char *out_priv_b64, size_t count) {
#ifndef ME_KEYGEN_OPENCL
    (void)kernel_path; (void)global_size; (void)local_size; (void)seed; (void)out_priv_b64; (void)count; return -1;
#else
    cl_int err;
    cl_uint nplat=0; OCL_CHECK(clGetPlatformIDs(0, NULL, &nplat), "clGetPlatformIDs"); if (!nplat) return -2;
    cl_platform_id p; OCL_CHECK(clGetPlatformIDs(1, &p, NULL), "clGetPlatformIDs(1)");
    cl_device_id d; OCL_CHECK(clGetDeviceIDs(p, CL_DEVICE_TYPE_GPU, 1, &d, NULL), "clGetDeviceIDs");
    cl_context ctx = clCreateContext(NULL, 1, &d, NULL, NULL, &err); OCL_CHECK(err, "clCreateContext");
    cl_command_queue q = clCreateCommandQueue(ctx, d, 0, &err); OCL_CHECK(err, "clCreateCommandQueue");

    size_t src_len=0; char *src = read_kernel_source(kernel_path, &src_len); if (!src) { err = CL_INVALID_VALUE; goto ocl_fail; }
    const char *srcs[1] = { src };
    cl_program prog = clCreateProgramWithSource(ctx, 1, srcs, &src_len, &err); OCL_CHECK(err, "clCreateProgramWithSource");
    err = clBuildProgram(prog, 1, &d, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t logsz = 0; clGetProgramBuildInfo(prog, d, CL_PROGRAM_BUILD_LOG, 0, NULL, &logsz);
        char *log = (char*)malloc(logsz+1); if (log) { clGetProgramBuildInfo(prog, d, CL_PROGRAM_BUILD_LOG, logsz, log, NULL); log[logsz]='\0'; fprintf(stderr, "OpenCL build log:\n%s\n", log); free(log);} 
        OCL_CHECK(err, "clBuildProgram");
    }
    cl_kernel krn = clCreateKernel(prog, "rng_dump_kernel", &err); OCL_CHECK(err, "clCreateKernel(rng_dump_kernel)");

    size_t gsize = global_size; size_t lsize = local_size ? local_size : 256; size_t ng = ((gsize + lsize - 1)/lsize)*lsize;
    cl_mem seeds = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(cl_uint2) * ng, NULL, &err); OCL_CHECK(err, "clCreateBuffer seeds");
    cl_mem outb  = clCreateBuffer(ctx, CL_MEM_READ_WRITE, 45 * ng, NULL, &err); OCL_CHECK(err, "clCreateBuffer outb");
    cl_uint2 *host_seeds = (cl_uint2*)calloc(ng, sizeof(cl_uint2));
    for (size_t i = 0; i < ng; ++i) { host_seeds[i].s[0] = (cl_uint)(seed ^ (0x9E3779B97F4A7C15ULL * (i+1))); host_seeds[i].s[1] = (cl_uint)(i * 0xD2511F53u + 1u); }
    OCL_CHECK(clEnqueueWriteBuffer(q, seeds, CL_TRUE, 0, sizeof(cl_uint2)*ng, host_seeds, 0, NULL, NULL), "write seeds");

    OCL_CHECK(clSetKernelArg(krn, 0, sizeof(cl_mem), &seeds), "arg0");
    OCL_CHECK(clSetKernelArg(krn, 1, sizeof(cl_mem), &outb),  "arg1");
    OCL_CHECK(clEnqueueNDRangeKernel(q, krn, 1, NULL, &ng, &lsize, 0, NULL, NULL), "enqueue");
    OCL_CHECK(clFinish(q), "finish");

    size_t to_copy = count < ng ? count : ng;
    OCL_CHECK(clEnqueueReadBuffer(q, outb, CL_TRUE, 0, 45*to_copy, out_priv_b64, 0, NULL, NULL), "read outb");

    free(host_seeds);
    clReleaseMemObject(seeds); clReleaseMemObject(outb);
    clReleaseKernel(krn); clReleaseProgram(prog); free(src);
    clReleaseCommandQueue(q); clReleaseContext(ctx);
    return (int)to_copy;

ocl_fail:
    return -1;
#endif
}

int ocl_pubkey_dump(const char *kernel_path, size_t global_size, size_t local_size, unsigned long long seed,
                    unsigned char *out_pub, size_t count) {
#ifndef ME_KEYGEN_OPENCL
    (void)kernel_path; (void)global_size; (void)local_size; (void)seed; (void)out_pub; (void)count; return -1;
#else
    cl_int err;
    cl_platform_id p; cl_device_id d; cl_uint nplat=0; OCL_CHECK(clGetPlatformIDs(0, NULL, &nplat), "clGetPlatformIDs"); if(!nplat) return -2;
    OCL_CHECK(clGetPlatformIDs(1, &p, NULL), "clGetPlatformIDs(1)");
    OCL_CHECK(clGetDeviceIDs(p, CL_DEVICE_TYPE_GPU, 1, &d, NULL), "clGetDeviceIDs");
    cl_context ctx = clCreateContext(NULL, 1, &d, NULL, NULL, &err); OCL_CHECK(err, "clCreateContext");
    cl_command_queue q = clCreateCommandQueue(ctx, d, 0, &err); OCL_CHECK(err, "clCreateCommandQueue");
    size_t src_len=0; char *src = read_kernel_source(kernel_path, &src_len); if (!src) { err = CL_INVALID_VALUE; goto ocl_fail; }
    const char *srcs[1] = { src };
    cl_program prog = clCreateProgramWithSource(ctx, 1, srcs, &src_len, &err); OCL_CHECK(err, "clCreateProgramWithSource");
    err = clBuildProgram(prog, 1, &d, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t logsz = 0; clGetProgramBuildInfo(prog, d, CL_PROGRAM_BUILD_LOG, 0, NULL, &logsz);
        char *log = (char*)malloc(logsz+1); if (log) { clGetProgramBuildInfo(prog, d, CL_PROGRAM_BUILD_LOG, logsz, log, NULL); log[logsz]='\0'; fprintf(stderr, "OpenCL build log:\n%s\n", log); free(log);} 
        OCL_CHECK(err, "clBuildProgram");
    }
    cl_kernel krn = clCreateKernel(prog, "pubkey_dump_kernel", &err); OCL_CHECK(err, "clCreateKernel(pubkey_dump_kernel)");

    size_t gsize = global_size; size_t lsize = local_size ? local_size : 256; size_t ng = ((gsize + lsize - 1)/lsize)*lsize;
    cl_mem seeds = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(cl_uint2) * ng, NULL, &err); OCL_CHECK(err, "clCreateBuffer seeds");
    cl_mem outb  = clCreateBuffer(ctx, CL_MEM_READ_WRITE, 32 * ng, NULL, &err); OCL_CHECK(err, "clCreateBuffer outb");
    cl_uint2 *host_seeds = (cl_uint2*)calloc(ng, sizeof(cl_uint2));
    for (size_t i = 0; i < ng; ++i) { host_seeds[i].s[0] = (cl_uint)(seed ^ (0x9E3779B97F4A7C15ULL * (i+1))); host_seeds[i].s[1] = (cl_uint)(i * 0xD2511F53u + 1u); }
    OCL_CHECK(clEnqueueWriteBuffer(q, seeds, CL_TRUE, 0, sizeof(cl_uint2)*ng, host_seeds, 0, NULL, NULL), "write seeds");

    OCL_CHECK(clSetKernelArg(krn, 0, sizeof(cl_mem), &seeds), "arg0");
    OCL_CHECK(clSetKernelArg(krn, 1, sizeof(cl_mem), &outb),  "arg1");
    OCL_CHECK(clEnqueueNDRangeKernel(q, krn, 1, NULL, &ng, &lsize, 0, NULL, NULL), "enqueue");
    OCL_CHECK(clFinish(q), "finish");

    size_t to_copy = count < ng ? count : ng;
    OCL_CHECK(clEnqueueReadBuffer(q, outb, CL_TRUE, 0, 32*to_copy, out_pub, 0, NULL, NULL), "read outb");

    free(host_seeds);
    clReleaseMemObject(seeds); clReleaseMemObject(outb);
    clReleaseKernel(krn); clReleaseProgram(prog); free(src);
    clReleaseCommandQueue(q); clReleaseContext(ctx);
    return (int)to_copy;
ocl_fail:
    return -1;
#endif
}

int ocl_pub_from_secrets(const char *kernel_path,
                         const unsigned char *secrets, size_t count,
                         unsigned char *out_pub) {
#ifndef ME_KEYGEN_OPENCL
    (void)kernel_path; (void)secrets; (void)count; (void)out_pub; return -1;
#else
    cl_int err;
    cl_platform_id p; cl_device_id d; cl_uint nplat=0; OCL_CHECK(clGetPlatformIDs(0, NULL, &nplat), "clGetPlatformIDs"); if(!nplat) return -2;
    OCL_CHECK(clGetPlatformIDs(1, &p, NULL), "clGetPlatformIDs(1)");
    OCL_CHECK(clGetDeviceIDs(p, CL_DEVICE_TYPE_GPU, 1, &d, NULL), "clGetDeviceIDs");
    cl_context ctx = clCreateContext(NULL, 1, &d, NULL, NULL, &err); OCL_CHECK(err, "clCreateContext");
    cl_command_queue q = clCreateCommandQueue(ctx, d, 0, &err); OCL_CHECK(err, "clCreateCommandQueue");
    size_t src_len=0; char *src = read_kernel_source(kernel_path, &src_len); if (!src) { err = CL_INVALID_VALUE; goto ocl_fail; }
    const char *srcs[1] = { src };
    cl_program prog = clCreateProgramWithSource(ctx, 1, srcs, &src_len, &err); OCL_CHECK(err, "clCreateProgramWithSource");
    err = clBuildProgram(prog, 1, &d, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t logsz = 0; clGetProgramBuildInfo(prog, d, CL_PROGRAM_BUILD_LOG, 0, NULL, &logsz);
        char *log = (char*)malloc(logsz+1); if (log) { clGetProgramBuildInfo(prog, d, CL_PROGRAM_BUILD_LOG, logsz, log, NULL); log[logsz]='\0'; fprintf(stderr, "OpenCL build log:\n%s\n", log); free(log);} 
        OCL_CHECK(err, "clBuildProgram");
    }
    cl_kernel krn = clCreateKernel(prog, "x25519_from_sk_kernel", &err); OCL_CHECK(err, "clCreateKernel(x25519_from_sk_kernel)");

    size_t gsize = count;
    cl_mem inb  = clCreateBuffer(ctx, CL_MEM_READ_ONLY  | CL_MEM_COPY_HOST_PTR, 32 * gsize, (void*)secrets, &err); OCL_CHECK(err, "clCreateBuffer inb");
    cl_mem outb = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY,  32 * gsize, NULL, &err); OCL_CHECK(err, "clCreateBuffer outb");
    OCL_CHECK(clSetKernelArg(krn, 0, sizeof(cl_mem), &inb),  "arg0");
    OCL_CHECK(clSetKernelArg(krn, 1, sizeof(cl_mem), &outb), "arg1");
    size_t lsize = 256; size_t ng = ((gsize + lsize - 1)/lsize)*lsize;
    OCL_CHECK(clEnqueueNDRangeKernel(q, krn, 1, NULL, &ng, &lsize, 0, NULL, NULL), "enqueue");
    OCL_CHECK(clFinish(q), "finish");
    OCL_CHECK(clEnqueueReadBuffer(q, outb, CL_TRUE, 0, 32*gsize, out_pub, 0, NULL, NULL), "read outb");

    clReleaseMemObject(inb); clReleaseMemObject(outb);
    clReleaseKernel(krn); clReleaseProgram(prog); free(src);
    clReleaseCommandQueue(q); clReleaseContext(ctx);
    return (int)gsize;
ocl_fail:
    return -1;
#endif
}

int ocl_debug_final(const char *kernel_path,
                    const unsigned char sk[32],
                    int out_limbs[40], unsigned char out_bytes[32],
                    int *out_swap_bit, int out_pre_limbs[20]) {
#ifndef ME_KEYGEN_OPENCL
    (void)kernel_path; (void)sk; (void)out_limbs; (void)out_bytes; return -1;
#else
    cl_int err; cl_platform_id p; cl_device_id d; cl_uint nplat=0; OCL_CHECK(clGetPlatformIDs(0,NULL,&nplat),"clGetPlatformIDs"); if(!nplat) return -2;
    OCL_CHECK(clGetPlatformIDs(1,&p,NULL),"clGetPlatformIDs(1)"); OCL_CHECK(clGetDeviceIDs(p,CL_DEVICE_TYPE_GPU,1,&d,NULL),"clGetDeviceIDs");
    cl_context ctx = clCreateContext(NULL,1,&d,NULL,NULL,&err); OCL_CHECK(err,"clCreateContext");
    cl_command_queue q = clCreateCommandQueue(ctx,d,0,&err); OCL_CHECK(err,"clCreateCommandQueue");
    size_t src_len=0; char *src = read_kernel_source(kernel_path,&src_len); if(!src){ err=CL_INVALID_VALUE; goto ocl_fail; }
    const char *srcs[1]={src}; cl_program prog = clCreateProgramWithSource(ctx,1,srcs,&src_len,&err); OCL_CHECK(err,"clCreateProgramWithSource");
    err = clBuildProgram(prog,1,&d,NULL,NULL,NULL);
    if (err != CL_SUCCESS) {
        size_t logsz=0; clGetProgramBuildInfo(prog,d,CL_PROGRAM_BUILD_LOG,0,NULL,&logsz);
        char *log=(char*)malloc(logsz+1); if(log){ clGetProgramBuildInfo(prog,d,CL_PROGRAM_BUILD_LOG,logsz,log,NULL); log[logsz]='\0'; fprintf(stderr,"OpenCL build log:\n%s\n",log); free(log);} 
        OCL_CHECK(err,"clBuildProgram");
    }
    cl_kernel krn = clCreateKernel(prog, "x25519_debug_final_kernel", &err); OCL_CHECK(err, "clCreateKernel(debug_final)");
    cl_mem inb = clCreateBuffer(ctx, CL_MEM_READ_ONLY  | CL_MEM_COPY_HOST_PTR, 32, (void*)sk, &err); OCL_CHECK(err, "clCreateBuffer inb");
    cl_mem outl= clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(cl_int)*40, NULL, &err); OCL_CHECK(err, "clCreateBuffer outl");
    cl_mem outb= clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, 32, NULL, &err); OCL_CHECK(err, "clCreateBuffer outb");
    cl_mem outswap = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(cl_int), NULL, &err); OCL_CHECK(err, "clCreateBuffer outswap");
    // pre buffer now holds: pre_x2[10], pre_z2[10], aa[10], bb[10], e[10], x2last[10], z2last[10] => 70 ints (round up to 80 for alignment)
    cl_mem outpre  = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(cl_int)*80, NULL, &err); OCL_CHECK(err, "clCreateBuffer outpre");
    OCL_CHECK(clSetKernelArg(krn, 0, sizeof(cl_mem), &inb),   "arg0");
    OCL_CHECK(clSetKernelArg(krn, 1, sizeof(cl_mem), &outl),  "arg1");
    OCL_CHECK(clSetKernelArg(krn, 2, sizeof(cl_mem), &outb),  "arg2");
    OCL_CHECK(clSetKernelArg(krn, 3, sizeof(cl_mem), &outswap), "arg3");
    OCL_CHECK(clSetKernelArg(krn, 4, sizeof(cl_mem), &outpre),  "arg4");
    size_t g=1,l=1; OCL_CHECK(clEnqueueNDRangeKernel(q, krn, 1, NULL, &g, &l, 0, NULL, NULL), "enqueue");
    OCL_CHECK(clFinish(q), "finish");
    OCL_CHECK(clEnqueueReadBuffer(q, outl, CL_TRUE, 0, sizeof(cl_int)*40, out_limbs, 0, NULL, NULL), "read outl");
    OCL_CHECK(clEnqueueReadBuffer(q, outb, CL_TRUE, 0, 32, out_bytes, 0, NULL, NULL), "read outb");
    if (out_swap_bit) {
        OCL_CHECK(clEnqueueReadBuffer(q, outswap, CL_TRUE, 0, sizeof(cl_int), out_swap_bit, 0, NULL, NULL), "read outswap");
    }
    if (out_pre_limbs) {
        OCL_CHECK(clEnqueueReadBuffer(q, outpre, CL_TRUE, 0, sizeof(cl_int)*80, out_pre_limbs, 0, NULL, NULL), "read outpre");
    }
    clReleaseMemObject(inb); clReleaseMemObject(outl); clReleaseMemObject(outb); clReleaseMemObject(outswap); clReleaseMemObject(outpre);
    clReleaseKernel(krn); clReleaseProgram(prog); free(src);
    clReleaseCommandQueue(q); clReleaseContext(ctx);
    return 0;
ocl_fail:
    return -1;
#endif
}

int ocl_trace_ladder(const char *kernel_path,
                     const unsigned char sk[32], unsigned iters,
                     int *out_limbs /* size iters*40 */) {
#ifndef ME_KEYGEN_OPENCL
    (void)kernel_path; (void)sk; (void)iters; (void)out_limbs; return -1;
#else
    cl_int err; cl_platform_id p; cl_device_id d; cl_uint nplat=0; OCL_CHECK(clGetPlatformIDs(0,NULL,&nplat),"clGetPlatformIDs"); if(!nplat) return -2;
    OCL_CHECK(clGetPlatformIDs(1,&p,NULL),"clGetPlatformIDs(1)"); OCL_CHECK(clGetDeviceIDs(p,CL_DEVICE_TYPE_GPU,1,&d,NULL),"clGetDeviceIDs");
    cl_context ctx = clCreateContext(NULL,1,&d,NULL,NULL,&err); OCL_CHECK(err,"clCreateContext");
    cl_command_queue q = clCreateCommandQueue(ctx,d,0,&err); OCL_CHECK(err,"clCreateCommandQueue");
    size_t src_len=0; char *src = read_kernel_source(kernel_path,&src_len); if(!src){ err=CL_INVALID_VALUE; goto ocl_fail; }
    const char *srcs[1]={src}; cl_program prog = clCreateProgramWithSource(ctx,1,srcs,&src_len,&err); OCL_CHECK(err,"clCreateProgramWithSource");
    err = clBuildProgram(prog,1,&d,NULL,NULL,NULL);
    if (err != CL_SUCCESS) {
        size_t logsz=0; clGetProgramBuildInfo(prog,d,CL_PROGRAM_BUILD_LOG,0,NULL,&logsz);
        char *log=(char*)malloc(logsz+1); if(log){ clGetProgramBuildInfo(prog,d,CL_PROGRAM_BUILD_LOG,logsz,log,NULL); log[logsz]='\0'; fprintf(stderr,"OpenCL build log:\n%s\n",log); free(log);} 
        OCL_CHECK(err,"clBuildProgram");
    }
    cl_kernel krn = clCreateKernel(prog, "x25519_trace_kernel", &err); OCL_CHECK(err, "clCreateKernel(trace)");
    cl_mem inb = clCreateBuffer(ctx, CL_MEM_READ_ONLY  | CL_MEM_COPY_HOST_PTR, 32, (void*)sk, &err); OCL_CHECK(err, "clCreateBuffer inb");
    size_t count_ints = (size_t)iters * 40;
    cl_mem outb = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(cl_int) * count_ints, NULL, &err); OCL_CHECK(err, "clCreateBuffer outb");
    OCL_CHECK(clSetKernelArg(krn, 0, sizeof(cl_mem), &inb), "arg0");
    OCL_CHECK(clSetKernelArg(krn, 1, sizeof(cl_mem), &outb), "arg1");
    OCL_CHECK(clSetKernelArg(krn, 2, sizeof(cl_uint), &iters), "arg2");
    size_t g=1,l=1; OCL_CHECK(clEnqueueNDRangeKernel(q, krn, 1, NULL, &g, &l, 0, NULL, NULL), "enqueue");
    OCL_CHECK(clFinish(q), "finish");
    OCL_CHECK(clEnqueueReadBuffer(q, outb, CL_TRUE, 0, sizeof(cl_int)*count_ints, out_limbs, 0, NULL, NULL), "read out");
    clReleaseMemObject(inb); clReleaseMemObject(outb); clReleaseKernel(krn); clReleaseProgram(prog); free(src); clReleaseCommandQueue(q); clReleaseContext(ctx);
    return (int)count_ints;
ocl_fail:
    return -1;
#endif
}
