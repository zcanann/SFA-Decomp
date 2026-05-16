#include "ghidra_import.h"
#include "main/dll/dll_A6.h"

extern u8 *pCamera;
extern u8 *lbl_803DD4BC;
extern s8 lbl_803DD4CA;
extern s16 lbl_803DB990;
extern f32 lbl_803E1628;
extern f32 lbl_803E162C;

extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z,
                                           f32 *outX, f32 *outY, f32 *outZ, void *xform);
extern void objRenderFn_8003b8f4(u8 *reticle, undefined4 a, undefined4 b, undefined4 c,
                        undefined4 d, f32 f);

#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: camcontrol_updateTargetReticle
 * EN v1.0 Address: 0x80100AA4
 * EN v1.0 Size: 492b
 */
void camcontrol_updateTargetReticle(u8 *fallbackTarget, int unused2,
                                    undefined4 arg3, undefined4 arg4,
                                    undefined4 arg5, undefined4 arg6)
{
  int savedReticleState;
  u8 savedReticleByte;
  u8 *reticle;
  u8 *target;
  u8 *otherTbl;
  u8 *slot;
  u8 idx;
  s8 mode;
  int paletteIdx;
  u16 *flagsObj;

  reticle = lbl_803DD4BC;
  target = fallbackTarget;
  if (*(u32 *)(pCamera + 0x120) != 0) {
    target = (u8 *)*(u32 *)(pCamera + 0x120);
    savedReticleState = lbl_803DD4CA;
    lbl_803DD4CA = 3;
    savedReticleByte = reticle[0x36];
    reticle[0x36] = 0xFF;
  }

  if (target != NULL) {
    if (*(u32 *)(target + 0x74) == 0) goto end;

    idx = target[0xE4];
    slot = (u8 *)*(u32 *)(target + 0x74) + idx * 0x18;
    otherTbl = (u8 *)*(u32 *)(target + 0x78);
    otherTbl = otherTbl + idx * 5;

    switch (*(otherTbl + 4) & 0xF) {
    case 1:
      mode = 0;
      break;
    case 4:
    case 9:
      mode = 2;
      break;
    default:
      mode = 1;
      break;
    }

    paletteIdx = (int)target[0xE8];
    if (paletteIdx >= 4) paletteIdx = 0;
    {
      u8 *paletteBase = (u8 *)*(u32 *)(target + 0x50);
      paletteBase = paletteBase + paletteIdx * 2;
      lbl_803DB990 = *(s16 *)(paletteBase + 0x7C);
    }

    *(f32 *)(reticle + 0x18) = *(f32 *)(slot + 0x0);
    *(f32 *)(reticle + 0x1C) = *(f32 *)(slot + 0x4);
    *(f32 *)(reticle + 0x20) = *(f32 *)(slot + 0x8);
    reticle[0xAD] = mode;

    *(u32 *)(reticle + 0x30) = *(u32 *)(target + 0x30);
    if (*(u32 *)(reticle + 0x30) != 0) {
      Obj_TransformWorldPointToLocal(*(f32 *)(reticle + 0x18),
                                     *(f32 *)(reticle + 0x1C),
                                     *(f32 *)(reticle + 0x20),
                                     (f32 *)(reticle + 0xC), (f32 *)(reticle + 0x10),
                                     (f32 *)(reticle + 0x14),
                                     (void *)*(u32 *)(reticle + 0x30));
    } else {
      *(f32 *)(reticle + 0xC) = *(f32 *)(reticle + 0x18);
      *(f32 *)(reticle + 0x10) = *(f32 *)(reticle + 0x1C);
      *(f32 *)(reticle + 0x14) = *(f32 *)(reticle + 0x20);
    }
    *(s16 *)(reticle + 0x2) = 0;
    *(s16 *)(reticle + 0x4) = 0;
    *(f32 *)(reticle + 0x8) = lbl_803E1628;
    reticle[0x37] = reticle[0x36];
    objRenderFn_8003b8f4(reticle, arg3, arg4, arg5, arg6, lbl_803E162C);
  } else {
    *(u32 *)(reticle + 0x30) = 0;
  }

  flagsObj = (u16 *)((u8 *)*(u32 *)(reticle + 0x7C) + (s8)reticle[0xAD] * 4);
  *(u16 *)((u8 *)flagsObj + 0x18) = (u16)(*(u16 *)((u8 *)flagsObj + 0x18) & 0xFFF7);

  if (*(u32 *)(pCamera + 0x120) != 0) {
    lbl_803DD4CA = (s8)savedReticleState;
    reticle[0x36] = savedReticleByte;
  }
end:
  ;
}
