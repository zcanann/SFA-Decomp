#include "ghidra_import.h"
#include "main/dll/CAM/dll_62.h"

extern void Obj_TransformWorldPointToLocal(f32 x,f32 y,f32 z,float *outX,float *outY,float *outZ,int obj);
extern uint getAngle();
extern undefined4 camcontrol_traceMove();
extern f32 fn_80293E80();
extern f32 sin();

extern u8 framesThisStep;
extern undefined4* lbl_803DCA50;
extern f32* lbl_803DD578;
extern f64 lbl_803E1990;
extern f64 lbl_803E1998;
extern f32 timeDelta;
extern f32 lbl_803E19A0;
extern f32 lbl_803E19A4;
extern f32 lbl_803E19A8;
extern f32 lbl_803E19AC;
extern f32 lbl_803E19B0;
extern f32 lbl_803E19B4;

/*
 * --INFO--
 *
 * Function: CameraModeClimb_update
 * EN v1.0 Address: 0x8010D36C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010D608
 * EN v1.1 Size: 1188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeClimb_update(short *param_1)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  short *psVar5;
  double dVar6;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  float local_bc;
  undefined4 local_b8;
  float local_b4;
  undefined auStack176 [112];
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  double local_20;
  undefined4 local_18;
  uint uStack20;

  psVar5 = *(short **)(param_1 + 0x52);
  if (*(short *)(lbl_803DD578 + 0xb) != 0) {
    *(ushort *)(lbl_803DD578 + 0xb) = *(short *)(lbl_803DD578 + 0xb) - (ushort)framesThisStep;
    if (*(short *)(lbl_803DD578 + 0xb) < 0) {
      *(undefined2 *)(lbl_803DD578 + 0xb) = 0;
    }
    uStack60 = (int)*(short *)((int)lbl_803DD578 + 0x2e) - (int)*(short *)(lbl_803DD578 + 0xb) ^
               0x80000000;
    local_40 = 0x43300000;
    uStack52 = (int)*(short *)((int)lbl_803DD578 + 0x2e) ^ 0x80000000;
    local_38 = 0x43300000;
    fVar1 = (float)((double)CONCAT44(0x43300000,uStack60) - lbl_803E1990) /
            (float)((double)CONCAT44(0x43300000,uStack52) - lbl_803E1990);
    uStack36 = (uint)*(ushort *)((int)lbl_803DD578 + 0x32);
    uStack44 = *(ushort *)(lbl_803DD578 + 0xd) - uStack36 ^ 0x80000000;
    local_30 = 0x43300000;
    local_28 = 0x43300000;
    *(short *)(lbl_803DD578 + 0xc) =
         (short)(int)(fVar1 * (float)((double)CONCAT44(0x43300000,uStack44) - lbl_803E1990) +
                     (float)((double)CONCAT44(0x43300000,uStack36) - lbl_803E1998));
    *lbl_803DD578 = fVar1 * (lbl_803DD578[6] - lbl_803DD578[5]) + lbl_803DD578[5];
    lbl_803DD578[3] = fVar1 * (lbl_803DD578[8] - lbl_803DD578[7]) + lbl_803DD578[7];
    lbl_803DD578[4] = fVar1 * (lbl_803DD578[10] - lbl_803DD578[9]) + lbl_803DD578[9];
  }
  local_d0 = *(float *)(psVar5 + 0xe) + lbl_803DD578[4];
  fVar2 = *(float *)(psVar5 + 0xe) + lbl_803DD578[3];
  fVar1 = *(float *)(param_1 + 0xe);
  if (fVar2 <= fVar1) {
    if (fVar1 <= local_d0) {
      local_d0 = lbl_803E19A0;
    }
    else {
      local_d0 = local_d0 - fVar1;
    }
  }
  else {
    local_d0 = fVar2 - fVar1;
  }
  local_d0 = local_d0 * lbl_803DD578[2] * timeDelta;
  *(float *)(param_1 + 0xe) = *(float *)(param_1 + 0xe) + local_d0;
  local_d8 = (*lbl_803DD578 - lbl_803DD578[1]) * lbl_803E19A4 * timeDelta;
  lbl_803DD578[1] = lbl_803DD578[1] + local_d8;
  local_20 = (double)CONCAT44(0x43300000,(int)*psVar5 ^ 0x80000000);
  dVar6 = (double)fn_80293E80((double)((lbl_803E19AC * (float)(local_20 - lbl_803E1990)) /
                                       lbl_803E19B0));
  local_bc = (float)((double)lbl_803E19A8 * dVar6 + (double)*(float *)(psVar5 + 0xc));
  local_b8 = *(undefined4 *)(psVar5 + 0xe);
  uStack36 = (int)*psVar5 ^ 0x80000000;
  local_28 = 0x43300000;
  dVar6 = (double)sin((double)((lbl_803E19AC *
                                        (float)((double)CONCAT44(0x43300000,uStack36) -
                                               lbl_803E1990)) / lbl_803E19B0));
  local_b4 = (float)((double)lbl_803E19A8 * dVar6 + (double)*(float *)(psVar5 + 0x10));
  uStack44 = (int)*psVar5 ^ 0x80000000;
  local_30 = 0x43300000;
  dVar6 = (double)fn_80293E80((double)((lbl_803E19AC *
                                        (float)((double)CONCAT44(0x43300000,uStack44) -
                                               lbl_803E1990)) / lbl_803E19B0));
  *(float *)(param_1 + 0xc) = (float)((double)lbl_803DD578[1] * dVar6 + (double)local_bc);
  uStack52 = (int)*psVar5 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar6 = (double)sin((double)((lbl_803E19AC *
                                        (float)((double)CONCAT44(0x43300000,uStack52) -
                                               lbl_803E1990)) / lbl_803E19B0));
  *(float *)(param_1 + 0x10) = (float)((double)lbl_803DD578[1] * dVar6 + (double)local_b4);
  camcontrol_traceMove((double)lbl_803E19B4,&local_bc,param_1 + 0xc,&local_c8,auStack176,3,1,1);
  *(undefined4 *)(param_1 + 0xc) = local_c8;
  *(undefined4 *)(param_1 + 0xe) = local_c4;
  *(undefined4 *)(param_1 + 0x10) = local_c0;
  uStack60 = (uint)*(ushort *)(lbl_803DD578 + 0xc);
  local_40 = 0x43300000;
  (**(code **)(*lbl_803DCA50 + 0x38))
            ((double)(float)((double)CONCAT44(0x43300000,uStack60) - lbl_803E1998),param_1,
             &local_cc,&local_d0,&local_d4,&local_d8,0);
  uVar3 = getAngle((double)local_cc,(double)local_d4);
  iVar4 = (0x8000 - (uVar3 & 0xffff)) - ((int)*param_1 & 0xffffU);
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  *param_1 = *param_1 + (short)iVar4;
  uStack20 = (uint)*(ushort *)(lbl_803DD578 + 0xc);
  local_18 = 0x43300000;
  local_d0 = *(float *)(param_1 + 0xe) -
             (*(float *)(psVar5 + 0xe) +
             (float)((double)CONCAT44(0x43300000,uStack20) - lbl_803E1998));
  uVar3 = getAngle((double)local_d0,(double)local_d8);
  iVar4 = (uVar3 & 0xffff) - ((int)param_1[1] & 0xffffU);
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  iVar4 = iVar4 * (uint)framesThisStep;
  param_1[1] = param_1[1] +
               ((short)((ulonglong)((longlong)iVar4 * 0x2aaaaaab) >> 0x20) -
               ((short)((short)(iVar4 / 0x60000) + (short)(iVar4 >> 0x1f)) >> 0xf));
  Obj_TransformWorldPointToLocal((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),
               *(int *)(param_1 + 0x18));
  return;
}
