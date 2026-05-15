#include "ghidra_import.h"
#include "main/dll/DIM/DIMExplosion.h"

extern undefined4 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern undefined4 ObjHitbox_SetStateIndex();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293900();
extern int FUN_80294dbc();

extern undefined4 DAT_80324800;
extern undefined4 DAT_80324802;
extern undefined4 DAT_80324804;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcb50;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e54f0;
extern f64 DOUBLE_803e5500;
extern f64 DOUBLE_803e5508;
extern f64 DOUBLE_803e5528;
extern f32 lbl_803DC078;
extern f32 lbl_803E54E4;
extern f32 lbl_803E54E8;
extern f32 lbl_803E54EC;
extern f32 lbl_803E54FC;
extern f32 lbl_803E5510;
extern f32 lbl_803E5518;
extern f32 lbl_803E551C;
extern f32 lbl_803E5520;

/*
 * --INFO--
 *
 * Function: FUN_801b13f0
 * EN v1.0 Address: 0x801B13F0
 * EN v1.0 Size: 1392b
 * EN v1.1 Address: 0x801B13F0
 * EN v1.1 Size: 1304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b13f0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  byte bVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  short sVar9;
  uint uVar10;
  int *piVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  short local_c8;
  short local_c4;
  short local_c2;
  undefined8 local_50;
  undefined8 local_40;
  
  piVar11 = *(int **)(param_9 + 0xb8);
  iVar7 = FUN_80017a98();
  bVar5 = DAT_803dc070;
  if (*piVar11 == 0) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  else {
    uVar10 = (uint)DAT_803dc070;
    sVar6 = (short)piVar11[2];
    iVar8 = (int)DAT_803dcb50;
    if ((int)sVar6 < iVar8 + -1) {
      local_c8 = sVar6 + -1;
      if (local_c8 < 0) {
        local_c8 = 0;
      }
      sVar9 = (short)(iVar8 + -1);
      local_c4 = sVar6 + 1;
      if (iVar8 <= (short)(sVar6 + 1)) {
        local_c4 = sVar9;
      }
      local_c2 = sVar6 + 2;
      if (iVar8 <= (short)(sVar6 + 2)) {
        local_c2 = sVar9;
      }
      iVar8 = (short)(sVar6 * 3) * 2;
      fVar1 = (float)((double)CONCAT44(0x43300000,
                                       (int)*(short *)(&DAT_80324800 + iVar8) ^ 0x80000000) -
                     DOUBLE_803e54f0) * lbl_803E54E4;
      dVar14 = (double)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(&DAT_80324802 + iVar8) ^ 0x80000000
                                                ) - DOUBLE_803e54f0) * lbl_803E54E4);
      fVar2 = (float)((double)CONCAT44(0x43300000,
                                       (int)*(short *)(&DAT_80324804 + iVar8) ^ 0x80000000) -
                     DOUBLE_803e54f0) * lbl_803E54E4;
      iVar8 = (short)(local_c4 * 3) * 2;
      fVar3 = (float)((double)CONCAT44(0x43300000,
                                       (int)*(short *)(&DAT_80324800 + iVar8) ^ 0x80000000) -
                     DOUBLE_803e54f0) * lbl_803E54E4;
      dVar15 = (double)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(&DAT_80324802 + iVar8) ^ 0x80000000
                                                ) - DOUBLE_803e54f0) * lbl_803E54E4);
      local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_80324804 + iVar8) ^ 0x80000000);
      fVar4 = (float)(local_50 - DOUBLE_803e54f0) * lbl_803E54E4;
      local_40 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(&DAT_80324802 + (short)(local_c2 * 3) * 2) ^
                                  0x80000000);
      if ((((float)(dVar15 - (double)((float)(local_40 - DOUBLE_803e54f0) * lbl_803E54E4)) <=
            lbl_803E54E8) &&
          ((float)(dVar14 - (double)((float)((double)CONCAT44(0x43300000,
                                                              (int)*(short *)(&DAT_80324802 +
                                                                             (short)(local_c8 * 3) *
                                                                             2) ^ 0x80000000) -
                                            DOUBLE_803e54f0) * lbl_803E54E4)) <= lbl_803E54E8))
         && (*(char *)(piVar11 + 3) < '\x01')) {
        FUN_80293900((double)(*(float *)(param_9 + 0x2c) * *(float *)(param_9 + 0x2c) +
                             *(float *)(param_9 + 0x24) * *(float *)(param_9 + 0x24) +
                             *(float *)(param_9 + 0x28) * *(float *)(param_9 + 0x28)));
        if ((*(ushort *)(iVar7 + 0xb0) & 0x1000) == 0) {
          FUN_80006824(param_9,0x1fb);
        }
        *(undefined *)(piVar11 + 3) = 0x1e;
      }
      dVar13 = (double)fVar1;
      dVar12 = (double)lbl_803E54E8;
      *(float *)(param_9 + 0xc) = (float)(dVar12 * (double)(float)((double)fVar3 - dVar13) + dVar13)
      ;
      *(float *)(param_9 + 0x10) = (float)(dVar12 * (double)(float)(dVar15 - dVar14) + dVar14);
      dVar14 = (double)fVar2;
      *(float *)(param_9 + 0x14) =
           (float)(dVar12 * (double)(float)((double)fVar4 - dVar14) + dVar14);
      *(float *)(param_9 + 0xc) = *(float *)(param_9 + 0xc) + *(float *)(*piVar11 + 0xc);
      *(float *)(param_9 + 0x10) = *(float *)(param_9 + 0x10) + *(float *)(*piVar11 + 0x10);
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + *(float *)(*piVar11 + 0x14);
      *(float *)(param_9 + 0x24) =
           lbl_803DC078 * (*(float *)(param_9 + 0xc) - *(float *)(param_9 + 0x80));
      *(float *)(param_9 + 0x28) =
           lbl_803DC078 * (*(float *)(param_9 + 0x10) - *(float *)(param_9 + 0x84));
      *(float *)(param_9 + 0x2c) =
           lbl_803DC078 * (*(float *)(param_9 + 0x14) - *(float *)(param_9 + 0x88));
      piVar11[2] = piVar11[2] + uVar10;
      if ('\0' < *(char *)(piVar11 + 3)) {
        *(byte *)(piVar11 + 3) = *(char *)(piVar11 + 3) - bVar5;
      }
      dVar14 = DOUBLE_803e54f0;
      fVar1 = lbl_803E54EC;
      *(short *)(param_9 + 2) =
           (short)(int)-(lbl_803E54EC * -*(float *)(param_9 + 0x2c) -
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(param_9 + 2) ^ 0x80000000) -
                               DOUBLE_803e54f0));
      *(short *)(param_9 + 4) =
           (short)(int)-(fVar1 * *(float *)(param_9 + 0x24) -
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(param_9 + 4) ^ 0x80000000) - dVar14
                               ));
      iVar7 = *(int *)(param_9 + 0x54);
      if (iVar7 != 0) {
        *(ushort *)(iVar7 + 0x60) = *(ushort *)(iVar7 + 0x60) | 1;
        *(undefined *)(iVar7 + 0x6e) = 4;
        *(undefined *)(iVar7 + 0x6f) = 2;
        *(undefined4 *)(iVar7 + 0x48) = 0x10;
        *(undefined4 *)(iVar7 + 0x4c) = 0x10;
      }
    }
    else {
      FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b1960
 * EN v1.0 Address: 0x801B1960
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801B1908
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b1960(int param_1,int param_2)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  piVar2[1] = *(int *)(param_2 + 0x14);
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  iVar1 = FUN_80017af8(piVar2[1]);
  *piVar2 = iVar1;
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x6a) = 0;
  }
  iVar1 = *(int *)(param_1 + 100);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0x810;
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b19e8
 * EN v1.0 Address: 0x801B19E8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B19B0
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b19e8(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b1a10
 * EN v1.0 Address: 0x801B1A10
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x801B19E4
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b1a10(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  short sVar1;
  ushort uVar2;
  double dVar3;
  uint uVar4;
  int iVar5;
  undefined2 *puVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar7;
  double dVar8;
  
  uVar4 = FUN_80017ae8();
  if ((uVar4 & 0xff) != 0) {
    psVar7 = *(short **)(param_9 + 0xb8);
    sVar1 = *psVar7;
    uVar2 = (ushort)DAT_803dc070;
    *psVar7 = sVar1 - uVar2;
    if ((short)(sVar1 - uVar2) < 1) {
      iVar5 = FUN_80017a98();
      iVar5 = FUN_80294dbc(iVar5);
      if (iVar5 == 0) {
        iVar5 = *(int *)(param_9 + 0x4c);
        puVar6 = FUN_80017aa4(0x24,0x196);
        *(undefined *)(puVar6 + 2) = *(undefined *)(iVar5 + 4);
        *(undefined *)(puVar6 + 3) = *(undefined *)(iVar5 + 6);
        *(undefined *)((int)puVar6 + 5) = *(undefined *)(iVar5 + 5);
        *(undefined *)((int)puVar6 + 7) = *(undefined *)(iVar5 + 7);
        *(undefined4 *)(puVar6 + 4) = *(undefined4 *)(param_9 + 0xc);
        *(undefined4 *)(puVar6 + 6) = *(undefined4 *)(param_9 + 0x10);
        *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(param_9 + 0x14);
        *(undefined4 *)(puVar6 + 10) = *(undefined4 *)(iVar5 + 0x14);
        *(undefined *)(puVar6 + 0xc) = *(undefined *)(iVar5 + 0x1c);
        puVar6[0xd] = (ushort)*(byte *)(iVar5 + 0x1a);
        uVar4 = randomGetRange(0,100);
        dVar3 = DOUBLE_803e5508;
        dVar8 = (double)((float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e5500)
                        / lbl_803E54FC);
        puVar6[0xe] = (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                                    (uint)*(byte *)(iVar5 + 0x1b)) -
                                                  DOUBLE_803e5508) + dVar8);
        FUN_80017ae4(dVar3,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,puVar6,5,
                     *(undefined *)(param_9 + 0xac),0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
        *psVar7 = psVar7[1];
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b1c08
 * EN v1.0 Address: 0x801B1C08
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B1BA8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b1c08(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b1c30
 * EN v1.0 Address: 0x801B1C30
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x801B1BDC
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b1c30(int param_1)
{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  
  pcVar6 = *(char **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  cVar1 = *pcVar6;
  if (cVar1 != '\x01') {
    if (cVar1 < '\x01') {
      if (-1 < cVar1) {
        if (*(char *)(*(int *)(param_1 + 0x54) + 0xb0) != '\x01') {
          ObjHitbox_SetStateIndex(param_1,*(int *)(param_1 + 0x54),1);
        }
        bVar2 = false;
        iVar4 = 0;
        iVar3 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
        if (0 < iVar3) {
          do {
            if (*(short *)(*(int *)(*(int *)(param_1 + 0x58) + iVar4 + 0x100) + 0x46) == 399) {
              bVar2 = true;
              break;
            }
            iVar4 = iVar4 + 4;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
        if (bVar2) {
          GameBit_Set((int)*(short *)(iVar5 + 0x1e),1);
          if (*(char *)(*(int *)(param_1 + 0x54) + 0xb0) != '\x02') {
            ObjHitbox_SetStateIndex(param_1,*(int *)(param_1 + 0x54),2);
          }
          *pcVar6 = '\x02';
        }
      }
    }
    else if ((cVar1 < '\x03') && (*(char *)(*(int *)(param_1 + 0x54) + 0xb0) != '\x02')) {
      ObjHitbox_SetStateIndex(param_1,*(int *)(param_1 + 0x54),2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b1d38
 * EN v1.0 Address: 0x801B1D38
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B1D04
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b1d38(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b1d3c
 * EN v1.0 Address: 0x801B1D3C
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x801B1DDC
 * EN v1.1 Size: 656b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b1d3c(void)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  double in_f30;
  double dVar5;
  double dVar6;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined auStack_68 [8];
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar1 = FUN_80286840();
  pcVar4 = *(char **)(uVar1 + 0xb8);
  iVar3 = *(int *)(uVar1 + 0x4c);
  *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) | 8;
  if (pcVar4[1] == '\0') {
    if (*pcVar4 < '\x01') {
      uStack_4c = (int)*(char *)(iVar3 + 0x19) ^ 0x80000000;
      local_50 = 0x43300000;
      local_60 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e5528) / lbl_803E5518;
      local_54 = lbl_803E551C;
      iVar2 = 0x2d;
      dVar5 = (double)lbl_803E5520;
      dVar6 = DOUBLE_803e5528;
      do {
        uStack_4c = randomGetRange(0xffffff06,0xfa);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_5c = local_60 *
                   (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - dVar6));
        uStack_44 = randomGetRange(0,0x1c2);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_58 = local_60 *
                   (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) - dVar6));
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x7f9,auStack_68,2,0xffffffff,0);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      iVar2 = 0x19;
      dVar5 = (double)lbl_803E5520;
      dVar6 = DOUBLE_803e5528;
      do {
        uStack_44 = randomGetRange(0xffffff06,0xfa);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_5c = local_60 *
                   (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) - dVar6));
        uStack_4c = randomGetRange(0,0x1c2);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_58 = local_60 *
                   (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - dVar6));
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x7fa,auStack_68,2,0xffffffff,0);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      if (*(int *)(iVar3 + 0x14) != 0x1d09) {
        FUN_80006824(uVar1,0x47b);
      }
      pcVar4[1] = '\x01';
      if ((int)*(short *)(iVar3 + 0x1e) != 0xffffffff) {
        GameBit_Set((int)*(short *)(iVar3 + 0x1e),1);
      }
    }
    else {
      iVar3 = FUN_80017a90();
      if (iVar3 != 0) {
        if ((*(byte *)(uVar1 + 0xaf) & 4) != 0) {
          (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,uVar1,1,4);
        }
        *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) & 0xf7;
        FUN_800400b0();
      }
    }
  }
  FUN_8028688c();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void dimsnowball1c2_free(void) {}
void dimsnowball1c2_hitDetect(void) {}
void dimsnowball1c2_release(void) {}
void dimsnowball1c2_initialise(void) {}
void dimgate_free(void) {}
void dimgate_hitDetect(void) {}
void dimgate_release(void) {}
void dimgate_initialise(void) {}
void dimbarrier_free(void) {}
void dimbarrier_hitDetect(void) {}
void dimbarrier_release(void) {}
void dimbarrier_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int dimsnowball1c2_func08(void) { return 0x0; }
int fn_801B15D8(void) { return 0x0; }
int dimgate_getExtraSize(void) { return 0x1; }
int dimgate_func08(void) { return 0x0; }
int dimicewall_getExtraSize(void) { return 0x2; }
int dimbarrier_getExtraSize(void) { return 0x4; }
int dimbarrier_func08(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4860;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4878;
extern f32 lbl_803E4898;
#pragma peephole off
void dimsnowball1c2_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4860); }
void dimgate_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4878); }
void dimbarrier_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4898); }
#pragma peephole reset
