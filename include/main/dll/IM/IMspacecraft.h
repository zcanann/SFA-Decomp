#ifndef MAIN_DLL_IM_IMSPACECRAFT_H_
#define MAIN_DLL_IM_IMSPACECRAFT_H_

#include "ghidra_import.h"

int SpiritDoorLock_getExtraSize(void);
int SpiritDoorLock_getObjectTypeId(void);
void SpiritDoorLock_free(int obj);
void SpiritDoorLock_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SpiritDoorLock_hitDetect(void);
void SpiritDoorLock_update(int obj);
void SpiritDoorLock_init(int obj, int *params, int mode);
void SpiritDoorLock_release(void);
void SpiritDoorLock_initialise(void);
void fn_801A5D88(int obj, int unused);
int RollingBarrel_getExtraSize(void);
int RollingBarrel_getObjectTypeId(void);
void RollingBarrel_free(int obj);
void RollingBarrel_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void RollingBarrel_hitDetect(void);
void RollingBarrel_update(int obj);
void RollingBarrel_init(int obj, int *params);
void RollingBarrel_release(void);
void RollingBarrel_initialise(void);
int MMP_LevelControl_SeqFn(int obj, int p2, u8 *seq);
int MMP_levelcontrol_getExtraSize(void);
int MMP_levelcontrol_getObjectTypeId(void);
void MMP_levelcontrol_free(int obj);
void MMP_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void MMP_levelcontrol_hitDetect(void);

#endif /* MAIN_DLL_IM_IMSPACECRAFT_H_ */
