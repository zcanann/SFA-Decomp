#include "ghidra_import.h"
#include "main/dll/SH/SHmushroom.h"

extern undefined4 FUN_8000da78();
extern undefined4 FUN_80021fac();
extern uint FUN_80022264();
extern undefined4 FUN_80022790();
extern void* FUN_8002becc();
extern undefined4 FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_8003613c();

extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e5ff8;
extern f32 FLOAT_803e5ff0;
extern f32 FLOAT_803e5ff4;
extern f32 FLOAT_803e6004;
extern f32 FLOAT_803e6008;
extern f32 FLOAT_803e600c;

/*
 * --INFO--
 *
 * Function: FUN_801d2e5c
 * EN v1.0 Address: 0x801D2E5C
 * EN v1.0 Size: 376b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801d2e5c(uint param_1)
{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  if (*(char *)(pfVar3 + 5) == '\0') {
    FUN_8000da78(param_1,0x3fd);
    iVar2 = *(int *)(param_1 + 0x4c);
    if ((*(byte *)((int)pfVar3 + 0x15) & 2) != 0) {
      *(byte *)((int)pfVar3 + 0x15) = *(byte *)((int)pfVar3 + 0x15) & 0xfd;
      uVar1 = FUN_80022264(0xffffffce,0x32);
      *pfVar3 = (float)((double)CONCAT44(0x43300000,
                                         (int)*(short *)(iVar2 + 0x1a) + uVar1 ^ 0x80000000) -
                       DOUBLE_803e5ff8);
    }
    if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7f1,0,2,0xffffffff,0);
    }
  }
  else {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    iVar2 = *(int *)(param_1 + 0x4c);
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar2 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar2 + 0xc);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar2 + 0x10);
    *(float *)(param_1 + 8) = FLOAT_803e5ff0;
    pfVar3[2] = FLOAT_803e5ff4;
    pfVar3[1] = pfVar3[3];
    pfVar3[4] = pfVar3[1] / pfVar3[2];
    *pfVar3 = pfVar3[2];
    FUN_8003613c(param_1);
    *(undefined *)(pfVar3 + 5) = 0;
    *(byte *)((int)pfVar3 + 0x15) = *(byte *)((int)pfVar3 + 0x15) | 2;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801d2fd4
 * EN v1.0 Address: 0x801D2FD4
 * EN v1.0 Size: 352b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2fd4(ushort *param_1)
{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_78;
  float local_74;
  float local_70;
  ushort local_6c;
  ushort local_6a;
  ushort local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float afStack_54 [18];
  
  iVar4 = *(int *)(param_1 + 0x26);
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    puVar3 = FUN_8002becc(0x24,0x198);
    local_6c = *param_1;
    local_6a = param_1[1];
    local_68 = param_1[2];
    local_60 = FLOAT_803e6004;
    local_5c = FLOAT_803e6004;
    local_58 = FLOAT_803e6004;
    local_64 = FLOAT_803e6008;
    FUN_80021fac(afStack_54,&local_6c);
    dVar5 = (double)FLOAT_803e6004;
    FUN_80022790(dVar5,(double)FLOAT_803e6008,dVar5,afStack_54,&local_78,&local_74,&local_70);
    dVar6 = (double)FLOAT_803e600c;
    local_60 = (float)(dVar6 * (double)local_78);
    local_5c = (float)(dVar6 * (double)local_74);
    local_58 = (float)(dVar6 * (double)local_70);
    *(float *)(puVar3 + 4) = *(float *)(param_1 + 6) + local_60;
    *(float *)(puVar3 + 6) = *(float *)(param_1 + 8) + local_5c;
    fVar1 = *(float *)(param_1 + 10);
    *(float *)(puVar3 + 8) = (float)((double)fVar1 + (double)local_58);
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)(puVar3 + 2) = 2;
    puVar3[0xd] = (short)((int)*(char *)(iVar4 + 0x1e) << 8);
    puVar3[0xe] = *param_1;
    FUN_8002e088((double)fVar1,dVar6,dVar5,in_f4,in_f5,in_f6,in_f7,in_f8,puVar3,5,0xff,0xffffffff,
                 (uint *)0x0,in_r8,in_r9,in_r10);
  }
  return;
}
