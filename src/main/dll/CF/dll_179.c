#include "ghidra_import.h"
#include "main/dll/CF/dll_179.h"

extern undefined4 FUN_8001d6e4();
extern undefined4 FUN_8001d7d8();
extern undefined4 FUN_8001d7f4();
extern undefined4 FUN_8001dadc();
extern undefined4 FUN_8001db7c();
extern undefined4 FUN_8001dbb4();
extern undefined4 FUN_8001dbf0();
extern undefined4 FUN_8001dc30();
extern undefined4 FUN_8001dcfc();
extern undefined4 FUN_8001de4c();
extern void* FUN_8001f58c();
extern uint FUN_80020078();
extern undefined4 FUN_80035c48();

extern undefined4* DAT_803dd6d8;
extern f64 DOUBLE_803e4a38;
extern f64 DOUBLE_803e4a40;
extern f32 FLOAT_803e4a10;
extern f32 FLOAT_803e4a14;
extern f32 FLOAT_803e4a18;
extern f32 FLOAT_803e4a20;
extern f32 FLOAT_803e4a24;
extern f32 FLOAT_803e4a28;
extern f32 FLOAT_803e4a2c;
extern f32 FLOAT_803e4a30;

/*
 * --INFO--
 *
 * Function: FUN_8018d74c
 * EN v1.0 Address: 0x8018D74C
 * EN v1.0 Size: 732b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018d74c(int param_1,int param_2)
{
  int iVar1;
  float fVar2;
  uint uVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined auStack_48 [8];
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  piVar7 = *(int **)(param_1 + 0xb8);
  uVar3 = (uint)*(byte *)(param_2 + 0x1a);
  if (uVar3 != 0) {
    local_40 = 0x43300000;
    *(float *)(param_1 + 8) =
         FLOAT_803e4a20 * (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4a38);
    uStack_3c = uVar3;
  }
  uVar3 = FUN_80020078(0x8c);
  if (uVar3 != 0) {
    *(byte *)((int)piVar7 + 0x11) = *(byte *)((int)piVar7 + 0x11) | 1;
  }
  *(undefined2 *)(piVar7 + 3) = *(undefined2 *)(param_2 + 0x18);
  if (((int)*(short *)(piVar7 + 3) != 0xffffffff) &&
     (uVar3 = FUN_80020078((int)*(short *)(piVar7 + 3)), uVar3 != 0)) {
    *(byte *)((int)piVar7 + 0x11) = *(byte *)((int)piVar7 + 0x11) | 4;
  }
  *(undefined *)(piVar7 + 4) = *(undefined *)(param_2 + 0x1b);
  fVar2 = *(float *)(param_1 + 8) / *(float *)(*(int *)(param_1 + 0x50) + 4);
  iVar6 = *(int *)(param_1 + 0x54);
  uStack_3c = (int)*(short *)(iVar6 + 0x5a) ^ 0x80000000;
  local_40 = 0x43300000;
  iVar5 = (int)((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4a40) * fVar2);
  local_38 = (longlong)iVar5;
  uStack_2c = (int)*(short *)(iVar6 + 0x5c) ^ 0x80000000;
  local_30 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e4a40) * fVar2);
  local_28 = (double)(longlong)iVar1;
  uStack_1c = (int)*(short *)(iVar6 + 0x5e) ^ 0x80000000;
  local_20 = 0x43300000;
  iVar6 = (int)((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4a40) * fVar2);
  local_18 = (longlong)iVar6;
  FUN_80035c48(param_1,(short)iVar5,(short)iVar1,(short)iVar6);
  piVar7[1] = (int)FLOAT_803e4a18;
  piVar7[2] = (int)FLOAT_803e4a10;
  if (*piVar7 == 0) {
    piVar4 = FUN_8001f58c(param_1,'\x01');
    *piVar7 = (int)piVar4;
  }
  if (*piVar7 != 0) {
    FUN_8001dbf0(*piVar7,2);
    FUN_8001dbb4(*piVar7,0xff,0x7f,0,0xff);
    FUN_8001dadc(*piVar7,0xff,0x7f,0,0xff);
    uStack_1c = (uint)(FLOAT_803e4a24 * *(float *)(param_1 + 8));
    local_18 = (longlong)(int)uStack_1c;
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    local_28 = (double)CONCAT44(0x43300000,uStack_1c);
    FUN_8001dcfc((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4a40),
                 (double)(FLOAT_803e4a28 + (float)(local_28 - DOUBLE_803e4a40)),*piVar7);
    iVar5 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_48);
    if (iVar5 == 0) {
      FUN_8001dc30((double)FLOAT_803e4a14,*piVar7,'\0');
    }
    else {
      FUN_8001dc30((double)FLOAT_803e4a14,*piVar7,'\x01');
    }
    dVar8 = (double)FLOAT_803e4a14;
    dVar9 = (double)FLOAT_803e4a2c;
    FUN_8001de4c(dVar8,dVar9,dVar8,(int *)*piVar7);
    FUN_8001d6e4(*piVar7,1,3);
    FUN_8001db7c(*piVar7,0xff,0x5c,0,0xff);
    FUN_8001d7f4((double)(FLOAT_803e4a30 * *(float *)(param_1 + 8)),dVar9,dVar8,in_f4,in_f5,in_f6,
                 in_f7,in_f8,*piVar7,0,0xff,0x7f,0,0x87,in_r9,in_r10);
    FUN_8001d7d8((double)FLOAT_803e4a28,*piVar7);
  }
  return;
}
