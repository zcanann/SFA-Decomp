#include "ghidra_import.h"
#include "main/dll/DR/DRearthwalk.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern double FUN_80017708();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a50();
extern int FUN_80017a5c();
extern undefined4 FUN_80017a6c();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305c4();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointLocalMtx();
extern undefined4 ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8004036c();
extern undefined4 FUN_80040a88();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80043030();
extern undefined4 FUN_80081110();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247734();
extern undefined4 FUN_80286834();
extern int FUN_8028683c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80294c30();
extern int FUN_80294cf8();
extern undefined4 FUN_80294d18();

extern undefined4 DAT_803dccc0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern f64 DOUBLE_803e6198;
extern f32 lbl_803DC074;
extern f32 lbl_803E6168;
extern f32 lbl_803E616C;
extern f32 lbl_803E6170;
extern f32 lbl_803E6174;
extern f32 lbl_803E6178;
extern f32 lbl_803E617C;
extern f32 lbl_803E6180;
extern f32 lbl_803E6184;
extern f32 lbl_803E6188;
extern f32 lbl_803E618C;
extern f32 lbl_803E6190;
extern f32 lbl_803E61A0;
extern f32 lbl_803E61A4;
extern f32 lbl_803E61A8;
extern f32 lbl_803E61AC;
extern f32 lbl_803E61B4;
extern f32 lbl_803E61B8;
extern f32 lbl_803E61C0;

/*
 * --INFO--
 *
 * Function: sh_staff_render
 * EN v1.0 Address: 0x801D9BDC
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801DA010
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void *Obj_GetPlayerObject(void);
extern void Obj_BuildWorldTransformMatrix(int obj, f32 *mtx, int p3);
extern void objRenderFn_8003b8f4(int obj, undefined4 p2, undefined4 p3, undefined4 p4,
                                  undefined4 p5, double scale);
extern void PSMTXInverse(int src, f32 *dst);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *dst);
extern void objSetMtxFn_800412d4(f32 *mtx);
extern void objRenderModel(int obj);
extern f32 timeDelta;
extern f32 lbl_803E54D0;
extern f32 lbl_803E54D4;
extern f32 lbl_803E54D8;
extern f32 lbl_803E54DC;
extern f32 lbl_803E54E0;
extern f32 lbl_803E54E4;
extern f32 lbl_803E54E8;
extern f32 lbl_803E54EC;
extern f32 lbl_803E54F0;
extern f32 lbl_803E54F4;
extern f32 lbl_803E54F8;

void sh_staff_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
  u8 *state;
  int player;
  int i;
  int j;
  u8 *ptr;
  int o;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 spd;
  f32 t;
  f32 scale;
  f32 bx;
  f32 cur2;
  f32 mtxB[12];
  f32 mtxA[12];
  f32 z0;
  f32 y0;
  f32 x0;
  f32 z1;
  f32 y1;
  f32 x1;

  state = *(u8 **)(obj + 0xb8);
  player = (int)Obj_GetPlayerObject();
  if (visible != 0) {
    if (state[0] == 3) {
      Obj_BuildWorldTransformMatrix(obj, mtxB, 0);
      PSMTXInverse((int)ObjPath_GetPointModelMtx((void *)player, 0), mtxA);
      PSMTXConcat(mtxA, mtxB, (f32 *)(state + 8));
      state[0] = 5;
    }
    if (state[0] == 4) {
      ObjPath_GetPointLocalMtx((void *)player, 0, (f32 *)(state + 8));
      state[0] = 5;
    }
    if (state[0] == 5) {
      PSMTXConcat((f32 *)ObjPath_GetPointModelMtx((void *)player, 0), (f32 *)(state + 8), mtxB);
      objSetMtxFn_800412d4(mtxB);
      objRenderModel(obj);
    } else {
      objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E54D0);
    }
    ObjPath_GetPointWorldPosition(obj, 0, &x0, &y0, &z0, 0);
    ObjPath_GetPointWorldPosition(obj, 1, &x1, &y1, &z1, 0);
    dx = x1 - x0;
    dy = y1 - y0;
    dz = z1 - z0;
    if (((state[2] & 1) != 0) && ((state[2] & 2) == 0)) {
      ptr = state + 8;
      for (i = 2; i < 10; i += 2) {
        if (*(uint *)(ptr + 0x38) == 0) {
          state[0x60 + i] = 1;
          break;
        }
        ptr += 8;
      }
      if (i >= 10) {
        state[2] |= 2;
      }
    }
    if (((state[2] & 4) != 0) && ((state[2] & 8) == 0)) {
      ptr = state + 4;
      for (i = 1; i < 10; i += 2) {
        if (*(uint *)(ptr + 0x38) == 0) {
          state[0x60 + i] = 1;
          break;
        }
        ptr += 8;
      }
      if (i >= 10) {
        state[2] |= 8;
      }
    }
    if (state[2] != 0) {
      if ((state[2] & 0x20) != 0) {
        i = 5;
        ptr = state + 0x14;
        for (; i < 5; i++) {
          o = *(int *)(ptr + 0x38);
          if ((uint)o != 0) {
            *(s16 *)(o + 6) |= 0x4000;
            *(int *)(ptr + 0x38) = 0;
          }
          ptr += 4;
        }
        if ((state[2] & 0x10) != 0) {
          *(f32 *)(state + 4) = *(f32 *)(state + 4) - timeDelta;
          if (*(f32 *)(state + 4) <= lbl_803E54D4) {
            spd = lbl_803E54D8;
          } else {
            *(f32 *)(state + 4) = *(f32 *)(state + 4) - timeDelta;
            spd = lbl_803E54DC * *(f32 *)(state + 4);
          }
        } else {
          *(f32 *)(state + 4) = *(f32 *)(state + 4) + timeDelta;
          if (*(f32 *)(state + 4) >= lbl_803E54E0) {
            *(f32 *)(state + 4) = lbl_803E54E0;
          }
          spd = lbl_803E54E4 * *(f32 *)(state + 4);
        }
        j = 0;
        ptr = state;
        for (; j < 5; j++) {
          if ((*(uint *)(ptr + 0x38) != 0) && (*(uint *)(state + 0x48) != 0)) {
            t = lbl_803E54E8 + (f32)j / lbl_803E54EC;
            bx = *(f32 *)(*(int *)(state + 0x48) + 0xc);
            *(f32 *)(*(int *)(ptr + 0x38) + 0xc) = t * (x0 - bx) + bx;
            *(f32 *)(*(int *)(ptr + 0x38) + 0x10) =
                t * (y0 - *(f32 *)(*(int *)(state + 0x48) + 0x10)) + *(f32 *)(*(int *)(state + 0x48) + 0x10);
            *(f32 *)(*(int *)(ptr + 0x38) + 0x14) =
                t * (z0 - *(f32 *)(*(int *)(state + 0x48) + 0x14)) + *(f32 *)(*(int *)(state + 0x48) + 0x14);
            *(f32 *)(*(int *)(ptr + 0x38) + 8) = spd;
          }
          ptr += 4;
        }
        j = 9;
        ptr = state + 0x24;
        for (; j > 4; j--) {
          if ((*(uint *)(ptr + 0x38) != 0) && (*(uint *)(state + 0x4c) != 0)) {
            t = lbl_803E54E8 + (f32)(9 - j) / lbl_803E54EC;
            bx = *(f32 *)(*(int *)(state + 0x4c) + 0xc);
            *(f32 *)(*(int *)(ptr + 0x38) + 0xc) = t * (x1 - bx) + bx;
            *(f32 *)(*(int *)(ptr + 0x38) + 0x10) =
                t * (y1 - *(f32 *)(*(int *)(state + 0x4c) + 0x10)) + *(f32 *)(*(int *)(state + 0x4c) + 0x10);
            *(f32 *)(*(int *)(ptr + 0x38) + 0x14) =
                t * (z1 - *(f32 *)(*(int *)(state + 0x4c) + 0x14)) + *(f32 *)(*(int *)(state + 0x4c) + 0x14);
            *(f32 *)(*(int *)(ptr + 0x38) + 8) = spd;
          }
          ptr -= 4;
        }
      } else {
        spd = lbl_803E54D8;
        if ((state[2] & 0x10) != 0) {
          *(f32 *)(state + 4) = *(f32 *)(state + 4) - timeDelta;
          if (*(f32 *)(state + 4) <= lbl_803E54D4) {
            state[2] &= ~0x10;
          } else {
            spd = lbl_803E54E4 * *(f32 *)(state + 4);
          }
        }
        for (j = 0; j < 10; j++) {
          if (*(uint *)(state + 0x38) != 0) {
            t = lbl_803E54F0 * (f32)j;
            t = t + (f32)(int)randomGetRange(-0x32, 0x32) / lbl_803E54F4;
            *(f32 *)(*(int *)(state + 0x38) + 0xc) = dx * t + x0;
            *(f32 *)(*(int *)(state + 0x38) + 0x10) = dy * t + y0;
            *(f32 *)(*(int *)(state + 0x38) + 0x14) = dz * t + z0;
            *(f32 *)(*(int *)(state + 0x38) + 8) = spd;
          }
          state += 4;
        }
      }
    } else {
      scale = lbl_803E54F8;
      cur2 = *(f32 *)(state + 4);
      bx = lbl_803E54D4;
      if (cur2 != bx) {
        *(f32 *)(state + 4) = cur2 - timeDelta;
        if (*(f32 *)(state + 4) <= bx) {
          o = *(int *)(state + 0x38);
          if ((uint)o != 0) {
            *(s16 *)(o + 6) |= 0x4000;
            *(int *)(state + 0x38) = 0;
            *(f32 *)(state + 4) = bx;
          }
        } else {
          scale = lbl_803E54E4 * *(f32 *)(state + 4);
        }
      }
      if (*(uint *)(state + 0x38) != 0) {
        *(f32 *)(*(int *)(state + 0x38) + 0xc) = dx * *(f32 *)(state + 0x6c) + x0;
        *(f32 *)(*(int *)(state + 0x38) + 0x10) = dy * *(f32 *)(state + 0x6c) + y0;
        *(f32 *)(*(int *)(state + 0x38) + 0x14) = dz * *(f32 *)(state + 0x6c) + z0;
        *(f32 *)(*(int *)(state + 0x38) + 8) = scale;
      }
    }
  }
}

/*
 * --INFO--
 *
 * Function: FUN_801d9cc4
 * EN v1.0 Address: 0x801D9CC4
 * EN v1.0 Size: 1656b
 * EN v1.1 Address: 0x801DA1CC
 * EN v1.1 Size: 1704b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d9cc4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  ushort *puVar5;
  int iVar6;
  float *pfVar7;
  char *pcVar8;
  uint uVar9;
  char *pcVar10;
  int iVar11;
  double in_f27;
  double dVar12;
  double in_f28;
  double dVar13;
  double in_f29;
  double dVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  float afStack_e0 [12];
  float afStack_b0 [12];
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  puVar5 = (ushort *)FUN_80286834();
  pcVar10 = *(char **)(puVar5 + 0x5c);
  iVar6 = FUN_80017a98();
  if (visible != 0) {
    if (*pcVar10 == '\x03') {
      FUN_80017a50(puVar5,afStack_b0,'\0');
      pfVar7 = (float *)ObjPath_GetPointModelMtx(iVar6,0);
      FUN_80247734(pfVar7,afStack_e0);
      FUN_80247618(afStack_e0,afStack_b0,(float *)(pcVar10 + 8));
      *pcVar10 = '\x05';
    }
    if (*pcVar10 == '\x04') {
      ObjPath_GetPointLocalMtx(iVar6,0,(float *)(pcVar10 + 8));
      *pcVar10 = '\x05';
    }
    if (*pcVar10 == '\x05') {
      pfVar7 = (float *)ObjPath_GetPointModelMtx(iVar6,0);
      FUN_80247618(pfVar7,(float *)(pcVar10 + 8),afStack_b0);
      FUN_8004036c(afStack_b0);
      FUN_80040a88((int)puVar5);
    }
    else {
      FUN_8003b818((int)puVar5);
    }
    ObjPath_GetPointWorldPosition(puVar5,0,&local_ec,&local_e8,&local_e4,0);
    ObjPath_GetPointWorldPosition(puVar5,1,&local_f8,&local_f4,&local_f0,0);
    dVar16 = (double)(local_f8 - local_ec);
    dVar15 = (double)(local_f4 - local_e8);
    dVar14 = (double)(local_f0 - local_e4);
    if (((pcVar10[2] & 1U) != 0) && ((pcVar10[2] & 2U) == 0)) {
      iVar6 = 2;
      iVar11 = 4;
      pcVar8 = pcVar10;
      do {
        if (*(int *)(pcVar8 + 0x40) == 0) {
          pcVar10[iVar6 + 0x60] = '\x01';
          break;
        }
        iVar6 = iVar6 + 2;
        iVar11 = iVar11 + -1;
        pcVar8 = pcVar8 + 8;
      } while (iVar11 != 0);
      if (9 < iVar6) {
        pcVar10[2] = pcVar10[2] | 2;
      }
    }
    if (((pcVar10[2] & 4U) != 0) && ((pcVar10[2] & 8U) == 0)) {
      iVar6 = 1;
      pcVar8 = pcVar10 + 4;
      iVar11 = 5;
      do {
        if (*(int *)(pcVar8 + 0x38) == 0) {
          pcVar10[iVar6 + 0x60] = '\x01';
          break;
        }
        pcVar8 = pcVar8 + 8;
        iVar6 = iVar6 + 2;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      if (9 < iVar6) {
        pcVar10[2] = pcVar10[2] | 8;
      }
    }
    fVar3 = lbl_803E6190;
    fVar2 = lbl_803E616C;
    bVar1 = pcVar10[2];
    if (bVar1 == 0) {
      if (*(float *)(pcVar10 + 4) != lbl_803E616C) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - lbl_803DC074;
        if (fVar2 < *(float *)(pcVar10 + 4)) {
          fVar3 = lbl_803E617C * *(float *)(pcVar10 + 4);
        }
        else {
          iVar6 = *(int *)(pcVar10 + 0x38);
          if (iVar6 != 0) {
            *(ushort *)(iVar6 + 6) = *(ushort *)(iVar6 + 6) | 0x4000;
            pcVar10[0x38] = '\0';
            pcVar10[0x39] = '\0';
            pcVar10[0x3a] = '\0';
            pcVar10[0x3b] = '\0';
            *(float *)(pcVar10 + 4) = fVar2;
          }
        }
      }
      if (*(int *)(pcVar10 + 0x38) != 0) {
        *(float *)(*(int *)(pcVar10 + 0x38) + 0xc) =
             (float)(dVar16 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_ec);
        *(float *)(*(int *)(pcVar10 + 0x38) + 0x10) =
             (float)(dVar15 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_e8);
        *(float *)(*(int *)(pcVar10 + 0x38) + 0x14) =
             (float)(dVar14 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_e4);
        *(float *)(*(int *)(pcVar10 + 0x38) + 8) = fVar3;
      }
    }
    else if ((bVar1 & 0x20) == 0) {
      dVar13 = (double)lbl_803E6170;
      if ((bVar1 & 0x10) != 0) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - lbl_803DC074;
        if (lbl_803E616C < *(float *)(pcVar10 + 4)) {
          dVar13 = (double)(lbl_803E617C * *(float *)(pcVar10 + 4));
        }
        else {
          pcVar10[2] = pcVar10[2] & 0xef;
        }
      }
      uVar9 = 0;
      do {
        if (*(int *)(pcVar10 + 0x38) != 0) {
          uStack_7c = uVar9 ^ 0x80000000;
          local_80 = 0x43300000;
          dVar12 = (double)(lbl_803E6188 *
                           (f32)(s32)uStack_7c);
          uStack_74 = randomGetRange(0xffffffce,0x32);
          dVar12 = (double)(float)(dVar12 + (double)((float)((double)CONCAT44(0x43300000,uStack_74)
                                                            - DOUBLE_803e6198) / lbl_803E618C));
          *(float *)(*(int *)(pcVar10 + 0x38) + 0xc) = (float)(dVar16 * dVar12 + (double)local_ec);
          *(float *)(*(int *)(pcVar10 + 0x38) + 0x10) = (float)(dVar15 * dVar12 + (double)local_e8);
          *(float *)(*(int *)(pcVar10 + 0x38) + 0x14) = (float)(dVar14 * dVar12 + (double)local_e4);
          *(float *)(*(int *)(pcVar10 + 0x38) + 8) = (float)dVar13;
        }
        pcVar10 = pcVar10 + 4;
        uVar9 = uVar9 + 1;
      } while ((int)uVar9 < 10);
    }
    else {
      pcVar8 = pcVar10 + 0x14;
      for (iVar6 = 5; iVar6 < 5; iVar6 = iVar6 + 1) {
        iVar11 = *(int *)(pcVar8 + 0x38);
        if (iVar11 != 0) {
          *(ushort *)(iVar11 + 6) = *(ushort *)(iVar11 + 6) | 0x4000;
          pcVar8[0x38] = '\0';
          pcVar8[0x39] = '\0';
          pcVar8[0x3a] = '\0';
          pcVar8[0x3b] = '\0';
        }
        pcVar8 = pcVar8 + 4;
      }
      if ((pcVar10[2] & 0x10U) == 0) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) + lbl_803DC074;
        if (lbl_803E6178 <= *(float *)(pcVar10 + 4)) {
          *(float *)(pcVar10 + 4) = lbl_803E6178;
        }
        fVar3 = lbl_803E617C * *(float *)(pcVar10 + 4);
      }
      else {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - lbl_803DC074;
        fVar3 = lbl_803E6170;
        if (lbl_803E616C < *(float *)(pcVar10 + 4)) {
          *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - lbl_803DC074;
          fVar3 = lbl_803E6174 * *(float *)(pcVar10 + 4);
        }
      }
      uVar9 = 0;
      iVar6 = 5;
      pcVar8 = pcVar10;
      do {
        if ((*(int *)(pcVar8 + 0x38) != 0) && (*(int *)(pcVar10 + 0x48) != 0)) {
          uStack_7c = uVar9 ^ 0x80000000;
          local_80 = 0x43300000;
          fVar4 = lbl_803E6180 +
                  (f32)(s32)uStack_7c / lbl_803E6184
          ;
          fVar2 = *(float *)(*(int *)(pcVar10 + 0x48) + 0xc);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0xc) = fVar4 * (local_ec - fVar2) + fVar2;
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x10) =
               fVar4 * (local_e8 - *(float *)(*(int *)(pcVar10 + 0x48) + 0x10)) +
               *(float *)(*(int *)(pcVar10 + 0x48) + 0x10);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x14) =
               fVar4 * (local_e4 - *(float *)(*(int *)(pcVar10 + 0x48) + 0x14)) +
               *(float *)(*(int *)(pcVar10 + 0x48) + 0x14);
          *(float *)(*(int *)(pcVar8 + 0x38) + 8) = fVar3;
        }
        pcVar8 = pcVar8 + 4;
        uVar9 = uVar9 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
      iVar6 = 9;
      pcVar8 = pcVar10 + 0x24;
      iVar11 = 5;
      do {
        if ((*(int *)(pcVar8 + 0x38) != 0) && (*(int *)(pcVar10 + 0x4c) != 0)) {
          uStack_7c = 9U - iVar6 ^ 0x80000000;
          local_80 = 0x43300000;
          fVar4 = lbl_803E6180 +
                  (f32)(s32)uStack_7c / lbl_803E6184
          ;
          fVar2 = *(float *)(*(int *)(pcVar10 + 0x4c) + 0xc);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0xc) = fVar4 * (local_f8 - fVar2) + fVar2;
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x10) =
               fVar4 * (local_f4 - *(float *)(*(int *)(pcVar10 + 0x4c) + 0x10)) +
               *(float *)(*(int *)(pcVar10 + 0x4c) + 0x10);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x14) =
               fVar4 * (local_f0 - *(float *)(*(int *)(pcVar10 + 0x4c) + 0x14)) +
               *(float *)(*(int *)(pcVar10 + 0x4c) + 0x14);
          *(float *)(*(int *)(pcVar8 + 0x38) + 8) = fVar3;
        }
        pcVar8 = pcVar8 + -4;
        iVar6 = iVar6 + -1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801da33c
 * EN v1.0 Address: 0x801DA33C
 * EN v1.0 Size: 664b
 * EN v1.1 Address: 0x801DA874
 * EN v1.1 Size: 548b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da33c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined2 *puVar4;
  int iVar5;
  undefined *puVar6;
  undefined *puVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  
  iVar1 = FUN_8028683c();
  puVar6 = *(undefined **)(iVar1 + 0xb8);
  iVar5 = 0;
  puVar7 = puVar6;
  uVar8 = extraout_f1;
  do {
    if (puVar6[iVar5 + 0x60] != '\0') {
      uVar2 = FUN_80017ae8();
      if ((uVar2 & 0xff) == 0) {
        iVar3 = 0;
      }
      else {
        puVar4 = FUN_80017aa4(0x20,0x659);
        *(undefined *)(puVar4 + 2) = 2;
        *(undefined *)((int)puVar4 + 7) = 0xff;
        iVar3 = FUN_80017a5c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             puVar4);
      }
      *(int *)(puVar7 + 0x38) = iVar3;
      puVar6[iVar5 + 0x60] = 0;
    }
    puVar7 = puVar7 + 4;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 10);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar5 = iVar5 + 1) {
    switch(*(undefined *)(param_11 + iVar5 + 0x81)) {
    case 2:
      *puVar6 = 3;
      break;
    case 3:
      puVar6[1] = 1;
      break;
    case 4:
      puVar6[1] = 0;
      break;
    case 5:
      FUN_801da5d4(iVar1,puVar6,1);
      break;
    case 6:
      *puVar6 = 4;
      break;
    case 7:
      FUN_8011e800(1);
      break;
    case 8:
      puVar6[2] = puVar6[2] | 1;
      break;
    case 9:
      puVar6[2] = puVar6[2] | 4;
      break;
    case 10:
      puVar6[2] = puVar6[2] | 0x10;
      *(float *)(puVar6 + 4) = lbl_803E6178;
      break;
    case 0xb:
      puVar6[2] = puVar6[2] | 0x20;
      *(float *)(puVar6 + 4) = lbl_803E616C;
      break;
    case 0xc:
      puVar6[2] = puVar6[2] | 0x10;
      puVar6[2] = puVar6[2] | 10;
      *(float *)(puVar6 + 4) = lbl_803E61A0;
    }
  }
  if (puVar6[1] != '\0') {
    (**(code **)(*DAT_803dd6e8 + 0x34))((int)*(short *)(*(int *)(iVar1 + 0x50) + 0x7e),0xa0,0x8c);
  }
  *(float *)(puVar6 + 0x6c) = lbl_803E6170 * lbl_803DC074 + *(float *)(puVar6 + 0x6c);
  if (lbl_803E6168 < *(float *)(puVar6 + 0x6c)) {
    *(float *)(puVar6 + 0x6c) = lbl_803E616C;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801da5d4
 * EN v1.0 Address: 0x801DA5D4
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x801DAA98
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da5d4(int param_1,undefined *param_2,int param_3)
{
  int iVar1;
  undefined *puVar2;
  int iVar3;
  
  iVar1 = FUN_80017a98();
  ObjHits_DisableObject(param_1);
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if (param_3 != 0) {
    FUN_80294c30(iVar1,1);
    FUN_80294d18(iVar1,1);
    iVar1 = 2;
    puVar2 = param_2;
    do {
      iVar3 = *(int *)(puVar2 + 0x38);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x38) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x3c);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x3c) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x40);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x40) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x44);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x44) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x48);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x48) = 0;
      }
      puVar2 = puVar2 + 0x14;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  *param_2 = 6;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801da724
 * EN v1.0 Address: 0x801DA724
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DABF8
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da724(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801da728
 * EN v1.0 Address: 0x801DA728
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801DAEB4
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da728(int param_1)
{
  float local_18;
  float local_14;
  float local_10;
  
  FUN_8003b818(param_1);
  local_18 = lbl_803E61B4;
  local_14 = lbl_803E61B8;
  local_10 = lbl_803E61B4;
  FUN_80081110(param_1,4,0,0,&local_18);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801da774
 * EN v1.0 Address: 0x801DA774
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801DAF14
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da774(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  if ((*(ushort *)(param_9 + 6) & 0x4000) != 0) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801da7f8
 * EN v1.0 Address: 0x801DA7F8
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x801DAF44
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801da7f8(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar1 + 4) = *(float *)(iVar1 + 4) + lbl_803DC074;
  if ((lbl_803E61C0 <= *(float *)(iVar1 + 4)) &&
     (*(float *)(iVar1 + 4) = *(float *)(iVar1 + 4) - lbl_803E61C0,
     (*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    FUN_80081110(param_1,0,2,0,(undefined4 *)0x0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801da868
 * EN v1.0 Address: 0x801DA868
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x801DAFD8
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da868(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int *piVar2;
  undefined8 uVar3;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  uVar3 = (**(code **)(*DAT_803dd6f8 + 0x18))();
  if (((param_10 == 0) && (iVar1 = *piVar2, iVar1 != 0)) &&
     ((*(ushort *)(iVar1 + 0xb0) & 0x40) == 0)) {
    FUN_80017ac8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
  }
  return;
}

/* 8b "li r3, N; blr" returners. */
int sh_beacon_getExtraSize(void) { return 0x18; }

extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);
extern void objRenderFn_8003b8f4(int obj, undefined4 p2, undefined4 p3, undefined4 p4,
                                  undefined4 p5, double scale);
extern void Obj_FreeObject(int obj);
extern void ObjHits_PollPriorityHitEffectWithCooldown(int obj, int a, int b, int c, int d,
                                                       int e, void* f);
extern undefined4* gExpgfxInterface;
extern f32 lbl_803E5518;
extern f32 lbl_803E551C;
extern f32 lbl_803E5520;
extern f32 lbl_803E5528;
extern f32 lbl_803E552C;
extern int lbl_803DDC00;
extern f32 timeDelta;

/* 96b: render via objRenderFn + fn_80098B18 with 3-float local. */
#pragma scheduling off
#pragma peephole off
void sh_staffhaze_render(int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5)
{
  float local[3];
  objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E5518);
  local[0] = lbl_803E551C;
  local[1] = lbl_803E5520;
  local[2] = lbl_803E551C;
  fn_80098B18(obj, *(float*)(obj + 8), 4, 0, 0, (int)&local[0]);
}
#pragma peephole reset
#pragma scheduling reset

/* 48b: free if 0x4000 flag set. */
#pragma peephole off
void sh_staffhaze_update(int obj)
{
  if ((*(short*)(obj + 6) & 0x4000) != 0) {
    Obj_FreeObject(obj);
  }
}
#pragma peephole reset

/* 120b: tick a float timer; on wrap optionally trigger an effect. */
#pragma scheduling off
#pragma peephole off
int sh_beacon_SeqFn(int obj)
{
  int extra = *(int*)(obj + 0xb8);
  *(float*)(extra + 4) = *(float*)(extra + 4) + timeDelta;
  if (*(float*)(extra + 4) >= lbl_803E5528) {
    *(float*)(extra + 4) = *(float*)(extra + 4) - lbl_803E5528;
    if ((*(unsigned short*)(obj + 0xb0) & 0x800) != 0) {
      fn_80098B18(obj, *(float*)(obj + 8), 0, 2, 0, 0);
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* 20b: reset extra->field_0x8 = lbl_803E552C, return 1. */
int fn_801DA9CC(int obj)
{
  *(float*)(*(int*)(obj + 0xb8) + 8) = lbl_803E552C;
  return 1;
}

/* 112b: vtable cleanup then maybe Obj_FreeObject. */
#pragma scheduling off
#pragma peephole off
void sh_beacon_free(int obj, int param_2)
{
  int extra = *(int*)(obj + 0xb8);
  (*(code*)(*(int*)gExpgfxInterface + 0x18))(obj);
  if (param_2 == 0) {
    void *p = *(void**)extra;
    if (p != NULL && (*(unsigned short*)((char*)p + 0xb0) & 0x40) == 0) {
      Obj_FreeObject((int)p);
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/* 56b: single-call hit-effect poll. */
#pragma scheduling off
void sh_emptytumblew_update(int obj)
{
  ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x280,
                                              &lbl_803DDC00);
}
#pragma scheduling reset

/* TODO stubs to align function set with v1.0 asm. Bodies are large
 * state-machine and animation logic; filling them is a follow-up task. */
extern int *gGameUIInterface;
extern u8 Obj_IsLoadingLocked(void);
extern int *Obj_AllocObjectSetup(int a, int b);
extern int loadObjectAtObject(int obj, int *setup);
extern void hudFn_8011f38c(int a);
extern void fn_801DA4A8(int obj, int state, int a);
extern f32 lbl_803E54D0;
extern f32 lbl_803E54D4;
extern f32 lbl_803E54D8;
extern f32 lbl_803E54E0;
extern f32 lbl_803E5508;
#pragma scheduling off
#pragma peephole off
int sh_staff_SeqFn(int obj, int unused, u8 *buf)
{
    int state = *(int *)(obj + 0xb8);
    int *p;
    int i;
    int pendingOffset;

    for (i = 0, p = (int *)state; i < 10; i++) {
        pendingOffset = i + 0x60;
        if (((u8 *)state)[pendingOffset] != 0) {
            int loadResult;
            if ((u8)Obj_IsLoadingLocked() == 0) {
                loadResult = 0;
            } else {
                int *newSetup = Obj_AllocObjectSetup(0x20, 0x659);
                *(u8 *)((char *)newSetup + 4) = 2;
                *(u8 *)((char *)newSetup + 7) = 0xff;
                loadResult = loadObjectAtObject(obj, newSetup);
            }
            *(int *)((char *)p + 0x38) = loadResult;
            ((u8 *)state)[pendingOffset] = 0;
        }
        p = (int *)((char *)p + 4);
    }

    for (i = 0; i < (int)buf[0x8b]; i++) {
        u8 v = buf[0x81 + i];
        switch (v) {
        case 0:
            *(u8 *)state = 3;
            break;
        case 1:
            *(u8 *)(state + 1) = 1;
            break;
        case 2:
            *(u8 *)(state + 1) = 0;
            break;
        case 3:
            fn_801DA4A8(obj, state, 1);
            break;
        case 4:
            *(u8 *)state = 4;
            break;
        case 5:
            hudFn_8011f38c(1);
            break;
        case 6:
            *(u8 *)(state + 2) = (u8)(*(u8 *)(state + 2) | 1);
            break;
        case 7:
            *(u8 *)(state + 2) = (u8)(*(u8 *)(state + 2) | 4);
            break;
        case 8:
            *(u8 *)(state + 2) = (u8)(*(u8 *)(state + 2) | 0x10);
            *(f32 *)(state + 4) = lbl_803E54E0;
            break;
        case 9:
            *(u8 *)(state + 2) = (u8)(*(u8 *)(state + 2) | 0x20);
            *(f32 *)(state + 4) = lbl_803E54D4;
            break;
        case 0xa:
            *(u8 *)(state + 2) = (u8)(*(u8 *)(state + 2) | 0x10);
            *(u8 *)(state + 2) = (u8)(*(u8 *)(state + 2) | 0xa);
            *(f32 *)(state + 4) = lbl_803E5508;
            break;
        case 0xb:
        case 0xc:
            break;
        }
    }

    if (*(u8 *)(state + 1) != 0) {
        ((void (*)(s16, int, int))((int *)*gGameUIInterface)[0x34 / 4])
            (*(s16 *)(*(int *)(obj + 0x50) + 0x7e), 0xa0, 0x8c);
    }
    *(f32 *)(state + 0x6c) = lbl_803E54D8 * timeDelta + *(f32 *)(state + 0x6c);
    if (*(f32 *)(state + 0x6c) > lbl_803E54D0) {
        *(f32 *)(state + 0x6c) = lbl_803E54D4;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
extern f32 lbl_803E5508;

extern f32 getXZDistance(f32 *a, f32 *b);
extern void *fn_802966CC(int player);
extern int fn_80295CF4(int player, int a);
extern int fn_8029672C(int player, int a);
extern void ObjAnim_SetMoveProgress(int obj, f32 p);
extern int ObjTrigger_IsSet(int obj);
extern u8 Obj_IsLoadingLocked(void);
extern int *Obj_AllocObjectSetup(int a, int b);
extern int loadObjectAtObject(int obj, int *setup);
extern void mapUnload(int idx, int flags);
extern void loadMapAndParent(int mapId);
extern void hudFn_8011f38c(int a);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int *gObjectTriggerInterface;
extern f32 lbl_803E54D0;
extern f32 lbl_803E54D4;
extern f32 lbl_803E54D8;
extern f32 lbl_803E54E0;
extern f32 lbl_803E550C;
extern f32 lbl_803E5510;
extern f32 lbl_803E5514;

#pragma scheduling off
#pragma peephole off
void fn_801DA4A8(int obj, int state, int clearChildren)
{
    int player;
    void *child;
    u8 *childSlots;
    int i;
    int zero;

    player = (int)Obj_GetPlayerObject();
    ObjHits_DisableObject(obj);
    *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) | 0x4000);
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);

    if (clearChildren != 0) {
        fn_80295CF4(player, 1);
        fn_8029672C(player, 1);
        zero = 0;
        childSlots = (u8 *)state;
        for (i = 0; i < 8; i += 4) {
            child = *(void **)(childSlots + 0x38);
            if (child != NULL) {
                *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
                *(int *)(childSlots + 0x38) = zero;
            }
            child = *(void **)(childSlots + 0x3c);
            if (child != NULL) {
                *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
                *(int *)(childSlots + 0x3c) = zero;
            }
            child = *(void **)(childSlots + 0x40);
            if (child != NULL) {
                *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
                *(int *)(childSlots + 0x40) = zero;
            }
            child = *(void **)(childSlots + 0x44);
            if (child != NULL) {
                *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
                *(int *)(childSlots + 0x44) = zero;
            }
            child = *(void **)(childSlots + 0x48);
            if (child != NULL) {
                *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
                *(int *)(childSlots + 0x48) = zero;
            }
            childSlots += 0x14;
        }
    }

    *(u8 *)state = 6;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void sh_staff_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    void *player = Obj_GetPlayerObject();
    f32 dist = getXZDistance((f32 *)(obj + 0x18), (f32 *)((int)player + 0x18));
    u8 mode = *(u8 *)state;

    if (mode == 0) {
        if (player == NULL) goto end;
        if (fn_802966CC((int)player) == 0) goto end;
        if (GameBit_Get(0x18b) != 0) {
            fn_801DA4A8(obj, *(int *)(obj + 0xb8), 0);
        } else {
            int loadResult;
            fn_80295CF4((int)player, 0);
            ObjAnim_SetMoveProgress(obj, lbl_803E54D0);
            *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);
            *(s16 *)(obj + 4) = (s16)(*(u8 *)(setup + 0x18) << 8);
            *(int (**)(int, int, u8 *))(obj + 0xbc) = sh_staff_SeqFn;
            *(u8 *)state = 1;
            if (Obj_IsLoadingLocked() == 0) {
                loadResult = 0;
            } else {
                int *newSetup = Obj_AllocObjectSetup(0x20, 0x659);
                *(u8 *)((char *)newSetup + 4) = 2;
                *(u8 *)((char *)newSetup + 7) = 0xff;
                loadResult = loadObjectAtObject(obj, newSetup);
            }
            *(int *)(state + 0x38) = loadResult;
            *(f32 *)(state + 0x70) = lbl_803E550C;
        }
    } else if (mode == 1) {
        if (ObjTrigger_IsSet(obj) != 0) {
            int target = ObjGroup_FindNearestObject(0xf, (u32)obj, 0);
            ((void (*)(int, int, int))((int *)*gObjectTriggerInterface)[0x48 / 4])(0, target, -1);
            *(u8 *)state = 2;
            *(f32 *)(state + 4) = lbl_803E54E0;
            GameBit_Set(0x18b, 1);
        } else if (dist > lbl_803E5510) {
            if (*(u8 *)(state + 3) != 0) {
                *(u8 *)(state + 3) = 0;
                mapUnload(0x13, 0x20000000);
            }
        } else if (dist < lbl_803E5514) {
            if (*(u8 *)(state + 3) == 0) {
                *(u8 *)(state + 3) = 1;
                loadMapAndParent(8);
            }
        }
    } else {
        if (*(u8 *)(state + 3) != 0) {
            *(u8 *)(state + 3) = 0;
            mapUnload(0x13, 0x20000000);
            GameBit_Set(0x3b8, 1);
        }
    }
end:
    hudFn_8011f38c(0);
    *(f32 *)(state + 0x6c) = lbl_803E54D8 * timeDelta + *(f32 *)(state + 0x6c);
    if (*(f32 *)(state + 0x6c) > lbl_803E54D0) {
        *(f32 *)(state + 0x6c) = lbl_803E54D4;
    }
    *(f32 *)(state + 0x70) = lbl_803E54D8 * timeDelta + *(f32 *)(state + 0x70);
    if (*(f32 *)(state + 0x70) > lbl_803E54D0) {
        *(f32 *)(state + 0x70) = lbl_803E54D4;
        if (*(u8 *)state == 1) {
            Sfx_PlayFromObject(obj, 0x3fe);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void sh_beacon_init(int obj, int defData)
{
    int state;
    int *setup;

    state = *(int *)(obj + 0xb8);
    *(s16 *)obj = (s16)((s32)*(s8 *)(defData + 0x18) << 8);
    *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x4000);

    *(u8 *)(state + 0x14) = (u8)GameBit_Get(*(s16 *)(defData + 0x1e));
    if (*(u8 *)(state + 0x14) == 0) {
        if (GameBit_Get(*(s16 *)(defData + 0x20)) != 0) {
            *(u8 *)(state + 0x14) = 2;
        }
    }

    if (*(u8 *)(state + 0x14) != 0 && Obj_IsLoadingLocked() != 0) {
        setup = Obj_AllocObjectSetup(0x20, 0x55);
        *(f32 *)((char *)setup + 8) = *(f32 *)(obj + 0xc);
        *(f32 *)((char *)setup + 0xc) = *(f32 *)(obj + 0x10);
        *(f32 *)((char *)setup + 0x10) = *(f32 *)(obj + 0x14);
        *(u8 *)((char *)setup + 4) = 2;
        *(u8 *)((char *)setup + 5) = *(u8 *)(*(int *)(obj + 0x4c) + 5);
        *(u8 *)((char *)setup + 7) = *(u8 *)(*(int *)(obj + 0x4c) + 7);
        *(int *)state = loadObjectAtObject(obj, setup);
    }

    *(void **)(obj + 0xbc) = sh_beacon_SeqFn;
}
#pragma peephole reset
#pragma scheduling reset
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern int GameBit_Set(int eventId, int value);
extern void gameBitDecrement(int eventId);
extern void *getTrickyObject(void);
extern void fn_8002B6D8(int obj, int p2, int p3, int p4, int p5, int p6);
extern f32 lbl_803E5528;
extern f32 lbl_803E5530;
extern f32 lbl_803E5534;
extern f32 lbl_803E5538;
extern f32 lbl_803E553C;
extern int lbl_803DDBF8;

typedef struct {
    u8 looping : 1;
    u8 rest : 7;
} BeaconFlags;

/*
 * --INFO--
 *
 * Function: sh_beacon_update
 * EN v1.0 Address: 0x801DAA58
 * EN v1.0 Size: 1080b
 */
void sh_beacon_update(int obj)
{
  u8 *state;
  int def;
  int tmp;
  int *setup;
  int mode;
  int state2;

  state = *(u8 **)(obj + 0xb8);
  def = *(int *)(obj + 0x4c);
  switch (state[0x14]) {
  case 0:
    if (((*(u8 *)(obj + 0xaf) & 1) != 0) &&
        ((*(int (*)(int))(*gGameUIInterface + 0x20))(0x194) != 0)) {
      gameBitDecrement(0x194);
      GameBit_Set(*(s16 *)(def + 0x20), 1);
      if (Obj_IsLoadingLocked() != 0) {
        setup = Obj_AllocObjectSetup(0x20, 0x55);
        *(f32 *)((char *)setup + 8) = *(f32 *)(obj + 0xc);
        *(f32 *)((char *)setup + 0xc) = *(f32 *)(obj + 0x10);
        *(f32 *)((char *)setup + 0x10) = *(f32 *)(obj + 0x14);
        *(u8 *)((char *)setup + 4) = 2;
        *(u8 *)((char *)setup + 5) = *(u8 *)(*(int *)(obj + 0x4c) + 5);
        *(u8 *)((char *)setup + 7) = *(u8 *)(*(int *)(obj + 0x4c) + 7);
        *(int *)state = loadObjectAtObject(obj, setup);
      }
      (*(code *)(*gObjectTriggerInterface + 0x48))(0, obj, -1);
      state[0x14] = 2;
    }
  case 2:
    state2 = *(int *)(obj + 0xb8);
    *(f32 *)(state2 + 4) = *(f32 *)(state2 + 4) + timeDelta;
    if (*(f32 *)(state2 + 4) >= lbl_803E5528) {
      *(f32 *)(state2 + 4) = *(f32 *)(state2 + 4) - lbl_803E5528;
      if ((*(u16 *)(obj + 0xb0) & 0x800) != 0) {
        fn_80098B18(obj, *(f32 *)(obj + 8), 0, 2, 0, 0);
      }
    }
    break;
  case 1:
    if ((((BeaconFlags *)(state + 0x15))->looping) == 0) {
      Sfx_AddLoopedObjectSound(obj, 0x9e);
      ((BeaconFlags *)(state + 0x15))->looping = 1;
    }
    if ((*(u16 *)(obj + 0xb0) & 0x800) != 0) {
      *(f32 *)(state + 0x10) = *(f32 *)(state + 0x10) + timeDelta;
      if (*(f32 *)(state + 0x10) > lbl_803E5530) {
        mode = 2;
        *(f32 *)(state + 0x10) = *(f32 *)(state + 0x10) - lbl_803E5530;
      } else {
        mode = 0;
      }
      *(f32 *)(state + 0xc) = *(f32 *)(state + 0xc) + timeDelta;
      if (*(f32 *)(state + 0xc) > lbl_803E5534) {
        *(f32 *)(state + 0xc) = *(f32 *)(state + 0xc) - lbl_803E5534;
        fn_80098B18(obj, *(f32 *)(obj + 8), 2, mode, 0, 0);
      }
    }
    break;
  }
  if (state[0x14] != 1) {
    *(u8 *)(obj + 0xaf) &= ~8;
    if (state[0x14] == 2) {
      fn_8002B6D8(obj, 0, 0, 0, 0, 8);
    } else if ((state[0x14] == 0) && (GameBit_Get(0x194) == 0)) {
      *(u8 *)(obj + 0xaf) |= 0x10;
    } else {
      *(u8 *)(obj + 0xaf) &= ~0x10;
    }
    tmp = (int)getTrickyObject();
    if (((void *)tmp != NULL) && ((*(u8 *)(obj + 0xaf) & 4) != 0)) {
      (*(code *)(*(int *)(*(int *)(tmp + 0x68)) + 0x28))(tmp, obj, 1, 4);
    }
  } else {
    if ((GameBit_Get(0x193) != 0) || (*(s16 *)(def + 0x1e) != 0x95)) {
      *(u8 *)(obj + 0xaf) |= 8;
    } else {
      *(u8 *)(obj + 0xaf) |= 0x10;
    }
  }
  if (*(f32 *)(state + 8) > lbl_803E5538) {
    *(f32 *)(state + 8) = *(f32 *)(state + 8) - timeDelta;
    if ((*(u16 *)(obj + 0xb0) & 0x800) != 0) {
      fn_80098B18(obj, lbl_803E553C * *(f32 *)(obj + 8), 3, 0, 0, 0);
    }
    if ((*(f32 *)(state + 8) <= lbl_803E5538) && (state[0x14] == 2)) {
      state[0x14] = 1;
      GameBit_Set(*(s16 *)(def + 0x1e), 1);
      if ((GameBit_Get(0x190) != 0) && (GameBit_Get(0x191) != 0) && (GameBit_Get(0x192) != 0)) {
        Sfx_PlayFromObject(0, 0x7e);
      } else {
        Sfx_PlayFromObject(0, 0x409);
      }
    }
  }
  ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129, &lbl_803DDBF8);
}
