#include "ghidra_import.h"
#include "main/dll/CF/CFguardian.h"

extern undefined4 FUN_80013ee8();
extern uint FUN_80020078();
extern int FUN_80021884();
extern undefined4 FUN_80021b8c();
extern uint FUN_80022264();
extern undefined4 FUN_80035ff8();
extern byte FUN_80067ad4();
extern undefined4 FUN_8006933c();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern undefined4 FUN_8018405c();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4 DAT_802c2a00;
extern undefined4 DAT_802c2a04;
extern undefined4 DAT_802c2a08;
extern undefined4 DAT_802c2a0c;
extern undefined4 DAT_802c2a10;
extern undefined4 DAT_802c2a14;
extern undefined4 DAT_803ad400;
extern undefined4 DAT_803ad404;
extern undefined4 DAT_803ad408;
extern undefined4 DAT_803ad40c;
extern undefined4 DAT_803de748;
extern f64 DOUBLE_803e4660;
extern f32 FLOAT_803e4644;
extern f32 FLOAT_803e4680;
extern f32 FLOAT_803e468c;
extern f32 FLOAT_803e4690;
extern f32 FLOAT_803e4694;
extern f32 FLOAT_803e4698;

/*
 * --INFO--
 *
 * Function: FUN_801846d8
 * EN v1.0 Address: 0x801846D8
 * EN v1.0 Size: 576b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801846d8(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80184918
 * EN v1.0 Address: 0x80184918
 * EN v1.0 Size: 572b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80184918(void)
{
  int iVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  uint auStack_108 [6];
  float local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  float local_c0 [12];
  undefined4 local_90 [16];
  float local_50 [4];
  undefined local_40 [4];
  undefined local_3c;
  int local_34 [13];
  
  iVar1 = FUN_80286840();
  iVar4 = *(int *)(iVar1 + 0x54);
  if (iVar4 != 0) {
    local_c0[0] = *(float *)(iVar1 + 0xc);
    local_c0[1] = *(float *)(iVar1 + 0x10);
    local_c0[2] = *(float *)(iVar1 + 0x14);
    local_f0 = *(float *)(iVar1 + 0x80);
    local_ec = *(undefined4 *)(iVar1 + 0x84);
    local_e8 = *(undefined4 *)(iVar1 + 0x88);
    local_50[0] = FLOAT_803e468c;
    local_40[0] = 0xff;
    local_3c = 3;
    trackDolphin_buildSweptBounds(auStack_108,&local_f0,local_c0,local_50,1);
    FUN_8006933c(iVar1,auStack_108,(uint)*(ushort *)(iVar4 + 0xb2),'\x01');
    bVar2 = FUN_80067ad4();
    if (bVar2 != 0) {
      if ((bVar2 & 1) == 0) {
        if ((bVar2 & 2) == 0) {
          if ((bVar2 & 4) == 0) {
            iVar3 = 3;
          }
          else {
            iVar3 = 2;
          }
        }
        else {
          iVar3 = 1;
        }
      }
      else {
        iVar3 = 0;
      }
      *(undefined *)(iVar4 + 0xac) = local_40[iVar3];
      *(float *)(iVar4 + 0x3c) = local_c0[iVar3 * 3];
      *(float *)(iVar4 + 0x40) = local_c0[iVar3 * 3 + 1];
      *(float *)(iVar4 + 0x44) = local_c0[iVar3 * 3 + 2];
      DAT_803ad400 = local_90[iVar3 * 4];
      DAT_803ad404 = local_90[iVar3 * 4 + 1];
      DAT_803ad408 = local_90[iVar3 * 4 + 2];
      DAT_803ad40c = local_90[iVar3 * 4 + 3];
      if (local_34[iVar3] == 0) {
        *(byte *)(iVar4 + 0xad) = *(byte *)(iVar4 + 0xad) | 1;
        *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar4 + 0x3c);
        *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar4 + 0x40);
        *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar4 + 0x44);
        *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar1 + 0x80);
        *(undefined4 *)(iVar4 + 0x14) = *(undefined4 *)(iVar1 + 0x84);
        *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(iVar1 + 0x88);
      }
      else {
        *(byte *)(iVar4 + 0xad) = *(byte *)(iVar4 + 0xad) | 2;
        *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar4 + 0x3c);
        *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar4 + 0x40);
        *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar4 + 0x44);
        *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar1 + 0x80);
        *(undefined4 *)(iVar4 + 0x14) = *(undefined4 *)(iVar1 + 0x84);
        *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(iVar1 + 0x88);
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80184b54
 * EN v1.0 Address: 0x80184B54
 * EN v1.0 Size: 492b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80184b54(ushort *param_1,int param_2,char param_3,float *param_4)
{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  double dVar4;
  double dVar5;
  float local_38;
  float local_34;
  float local_30;
  ushort local_2c [4];
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  puVar3 = *(undefined4 **)(param_1 + 0x5c);
  if (param_3 == '\x01') {
    local_38 = *(float *)(param_2 + 4);
    local_34 = *(float *)(param_2 + 8);
    local_30 = *(float *)(param_2 + 0xc);
  }
  else if (param_3 == '\0') {
    local_38 = *param_4;
    local_34 = param_4[1];
    local_30 = param_4[2];
  }
  else if (param_3 == '\x02') {
    *(float *)(param_1 + 0x12) = *param_4;
    *(float *)(param_1 + 0x16) = param_4[2];
    dVar5 = (double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                    *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16));
    if (dVar5 != (double)FLOAT_803e4690) {
      dVar5 = FUN_80293900(dVar5);
    }
    dVar4 = (double)FLOAT_803e4694;
    *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) / (float)(dVar4 * dVar5);
    *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) / (float)(dVar4 * dVar5);
    *puVar3 = *(undefined4 *)(param_1 + 0x12);
    puVar3[1] = *(undefined4 *)(param_1 + 0x16);
    iVar1 = FUN_80021884();
    *param_1 = (ushort)iVar1;
    return;
  }
  local_20 = FLOAT_803e4690;
  local_1c = FLOAT_803e4690;
  local_18 = FLOAT_803e4690;
  local_24 = FLOAT_803e4698;
  local_2c[2] = 0;
  local_2c[1] = 0;
  local_2c[0] = *param_1;
  FUN_80021b8c(local_2c,&local_38);
  if (param_2 == 0) {
    param_1[2] = 0;
    iVar1 = FUN_80021884();
    param_1[1] = (ushort)iVar1;
    if ((short)param_1[1] < 0) {
      param_1[1] = -param_1[1];
    }
    iVar1 = FUN_80021884();
    *param_1 = (ushort)iVar1;
  }
  else {
    iVar1 = FUN_80021884();
    iVar2 = FUN_80021884();
    param_1[1] = (ushort)iVar2;
    param_1[2] = (ushort)iVar1;
  }
  return;
}
