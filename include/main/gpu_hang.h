#ifndef MAIN_GPU_HANG_H_
#define MAIN_GPU_HANG_H_

/* Selects the diagnostic XF/setup/raster counters, replacing normal metrics.
 * The enable argument retains the retail low-byte test.
 */
void videoSetGpuHangMetricsEnabled(int enabled);
void logGpuHang(void);
void gxDisableGpuHangRecovery(void);

#endif /* MAIN_GPU_HANG_H_ */
