#include "ghidra_import.h"
#include "main/dll/CAM/dll_62.h"


#pragma peephole off
#pragma scheduling off
extern void Obj_TransformWorldPointToLocal(f32 x,f32 y,f32 z,float *outX,float *outY,float *outZ,int obj);
extern uint getAngle();
extern undefined4 camcontrol_traceMove();
extern f32 fn_80293E80();
extern f32 sin();

extern u8 framesThisStep;
extern undefined4* gCameraInterface;
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
  f32 fVar1;
  f32 fVar2;
  uint uVar3;
  int iVar4;
  short *psVar5;
  f64 dVar6;
  f32 local_d8;
  f32 local_d4;
  f32 local_d0;
  f32 local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  f32 local_bc;
  undefined4 local_b8;
  f32 local_b4;
  undefined auStack176 [112];

  psVar5 = *(short **)(param_1 + 0x52);
  if (*(short *)(lbl_803DD578 + 0xb) != 0) {
    *(ushort *)(lbl_803DD578 + 0xb) = *(short *)(lbl_803DD578 + 0xb) - (ushort)framesThisStep;
    if (*(short *)(lbl_803DD578 + 0xb) < 0) {
      *(undefined2 *)(lbl_803DD578 + 0xb) = 0;
    }
    fVar1 = (f32)(s32)(*(s16 *)((int)lbl_803DD578 + 0x2e) - *(s16 *)(lbl_803DD578 + 0xb)) /
            (f32)(s32)*(s16 *)((int)lbl_803DD578 + 0x2e);
    *(short *)(lbl_803DD578 + 0xc) =
         (short)(int)(fVar1 * (f32)(s32)(*(u16 *)(lbl_803DD578 + 0xd) - *(u16 *)((int)lbl_803DD578 + 0x32)) +
                     (f32)(u32)*(u16 *)((int)lbl_803DD578 + 0x32));
    *lbl_803DD578 = fVar1 * (lbl_803DD578[6] - lbl_803DD578[5]) + lbl_803DD578[5];
    lbl_803DD578[3] = fVar1 * (lbl_803DD578[8] - lbl_803DD578[7]) + lbl_803DD578[7];
    lbl_803DD578[4] = fVar1 * (lbl_803DD578[10] - lbl_803DD578[9]) + lbl_803DD578[9];
  }
  local_d0 = *(f32 *)(psVar5 + 0xe) + lbl_803DD578[4];
  fVar2 = *(f32 *)(psVar5 + 0xe) + lbl_803DD578[3];
  fVar1 = *(f32 *)(param_1 + 0xe);
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
  *(f32 *)(param_1 + 0xe) = *(f32 *)(param_1 + 0xe) + local_d0;
  local_d8 = (*lbl_803DD578 - lbl_803DD578[1]) * lbl_803E19A4 * timeDelta;
  lbl_803DD578[1] = lbl_803DD578[1] + local_d8;
  dVar6 = (f64)fn_80293E80((f64)((lbl_803E19AC * (f32)(s32)*psVar5) / lbl_803E19B0));
  local_bc = (f32)((f64)lbl_803E19A8 * dVar6 + (f64)*(f32 *)(psVar5 + 0xc));
  local_b8 = *(undefined4 *)(psVar5 + 0xe);
  dVar6 = (f64)sin((f64)((lbl_803E19AC * (f32)(s32)*psVar5) / lbl_803E19B0));
  local_b4 = (f32)((f64)lbl_803E19A8 * dVar6 + (f64)*(f32 *)(psVar5 + 0x10));
  dVar6 = (f64)fn_80293E80((f64)((lbl_803E19AC * (f32)(s32)*psVar5) / lbl_803E19B0));
  *(f32 *)(param_1 + 0xc) = (f32)((f64)lbl_803DD578[1] * dVar6 + (f64)local_bc);
  dVar6 = (f64)sin((f64)((lbl_803E19AC * (f32)(s32)*psVar5) / lbl_803E19B0));
  *(f32 *)(param_1 + 0x10) = (f32)((f64)lbl_803DD578[1] * dVar6 + (f64)local_b4);
  camcontrol_traceMove((f64)lbl_803E19B4,&local_bc,param_1 + 0xc,&local_c8,auStack176,3,1,1);
  *(undefined4 *)(param_1 + 0xc) = local_c8;
  *(undefined4 *)(param_1 + 0xe) = local_c4;
  *(undefined4 *)(param_1 + 0x10) = local_c0;
  (**(code **)(*gCameraInterface + 0x38))
            ((f64)(f32)(u32)*(u16 *)(lbl_803DD578 + 0xc),param_1,
             &local_cc,&local_d0,&local_d4,&local_d8,0);
  uVar3 = getAngle((f64)local_cc,(f64)local_d4);
  iVar4 = (0x8000 - (uVar3 & 0xffff)) - ((int)*param_1 & 0xffffU);
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  *param_1 = *param_1 + (short)iVar4;
  local_d0 = *(f32 *)(param_1 + 0xe) -
             (*(f32 *)(psVar5 + 0xe) + (f32)(u32)*(u16 *)(lbl_803DD578 + 0xc));
  uVar3 = getAngle((f64)local_d0,(f64)local_d8);
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
  Obj_TransformWorldPointToLocal((f64)*(f32 *)(param_1 + 0xc),(f64)*(f32 *)(param_1 + 0xe),
               (f64)*(f32 *)(param_1 + 0x10),(f32 *)(param_1 + 6),(f32 *)(param_1 + 8),
               (f32 *)(param_1 + 10),
               *(int *)(param_1 + 0x18));
}
