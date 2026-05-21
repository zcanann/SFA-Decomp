#include "ghidra_import.h"
#include "main/dll/DIM/DIMsnowball.h"

extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern undefined4 FUN_80006c88();
extern undefined4 FUN_80017680();
extern undefined4 FUN_80017688();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017708();
extern double FUN_80017714();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a6c();
extern undefined4 FUN_80017a78();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern int ObjHits_PollPriorityHitWithCooldown();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern int ObjTrigger_IsSetById();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80048000();
extern undefined4 FUN_8004800c();
extern undefined4 FUN_80080f14();
extern undefined4 FUN_800810e8();
extern undefined4 FUN_800810f8();
extern undefined4 FUN_80081120();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_801141e8();
extern undefined4 FUN_801149bc();
extern undefined4 FUN_80114b10();
extern undefined4 dll_2E_func03();
extern undefined4 FUN_801150ac();
extern undefined4 FUN_8012f744();
extern char FUN_80132034();
extern double FUN_8014cbcc();
extern undefined4 FUN_8014ccac();
extern undefined4 FUN_801aa4a4();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern undefined4 FUN_80286834();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern byte FUN_80294c20();
extern int FUN_80294c54();

extern undefined4 DAT_80324048;
extern undefined4 DAT_80324058;
extern undefined4 DAT_80324068;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de7b8;
extern undefined4 DAT_803e52e8;
extern undefined4 DAT_803e52ec;
extern undefined4 DAT_803e52f0;
extern undefined4 DAT_803e52f4;
extern f64 DOUBLE_803e52e0;
extern f64 DOUBLE_803e5338;
extern f32 lbl_803DC074;
extern f32 lbl_803E52B0;
extern f32 lbl_803E52B4;
extern f32 lbl_803E52BC;
extern f32 lbl_803E52C0;
extern f32 lbl_803E52C4;
extern f32 lbl_803E52C8;
extern f32 lbl_803E52CC;
extern f32 lbl_803E52D0;
extern f32 lbl_803E52D4;
extern f32 lbl_803E52D8;
extern f32 lbl_803E52FC;
extern f32 lbl_803E5300;
extern f32 lbl_803E5308;
extern f32 lbl_803E530C;
extern f32 lbl_803E5310;
extern f32 lbl_803E5314;
extern f32 lbl_803E5318;
extern f32 lbl_803E531C;
extern f32 lbl_803E5320;
extern f32 lbl_803E5324;
extern f32 lbl_803E5328;
extern f32 lbl_803E5330;
extern f32 lbl_803E5340;
extern f32 lbl_803E5344;
extern f32 lbl_803E5348;
extern f32 lbl_803E534C;
extern f32 lbl_803E5350;
extern f32 lbl_803E5354;
extern f32 lbl_803E5358;
extern f32 lbl_803E535C;
extern f32 lbl_803E5360;
extern f32 lbl_803E5368;

/*
 * --INFO--
 *
 * Function: ccqueen_render
 * EN v1.0 Address: 0x801AA560
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x801AA584
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ccqueen_render(void)
{
  char cVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  byte bVar7;
  double dVar8;
  double in_f31;
  double dVar9;
  double in_ps31_1;
  undefined8 uVar10;
  int aiStack_38 [12];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar10 = FUN_8028683c();
  uVar2 = (uint)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  cVar1 = '\0';
  uVar3 = GameBit_Get(0x1c0);
  if (uVar3 != 0) {
    puVar4 = ObjGroup_GetObjects(0x3f,aiStack_38);
    dVar9 = (double)lbl_803E52B0;
    for (bVar7 = 0; bVar7 < 4; bVar7 = bVar7 + 1) {
      iVar5 = ObjGroup_FindNearestObject(5,puVar4[bVar7],(float *)0x0);
      dVar8 = FUN_80017708((float *)(puVar4[bVar7] + 0x18),(float *)(iVar5 + 0x18));
      if (dVar9 < dVar8) {
        cVar1 = cVar1 + '\x01';
      }
    }
  }
  if (cVar1 == '\0') {
    if (*(char *)(iVar6 + 1) != '\0') {
      FUN_800068cc();
      *(undefined *)(iVar6 + 1) = 0;
    }
  }
  else {
    if (*(char *)(iVar6 + 1) == '\0') {
      FUN_800068d0(uVar2,0x223);
      *(undefined *)(iVar6 + 1) = 1;
    }
    FUN_80006818((double)lbl_803E52B4,uVar2,0x223,cVar1 * '\x0f' + 0x28);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aa684
 * EN v1.0 Address: 0x801AA684
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801AA6C0
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa684(int param_1)
{
  if ((**(char **)(param_1 + 0xb8) == '\x03') || (**(char **)(param_1 + 0xb8) == '\x04')) {
    FUN_80048000();
  }
  (**(code **)(*DAT_803dd6e8 + 0x60))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aa6d8
 * EN v1.0 Address: 0x801AA6D8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801AA70C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa6d8(int param_1)
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
 * Function: FUN_801aa700
 * EN v1.0 Address: 0x801AA700
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AA73C
 * EN v1.1 Size: 884b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa700(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801aa704
 * EN v1.0 Address: 0x801AA704
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AAAB0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa704(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801aa708
 * EN v1.0 Address: 0x801AA708
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801AAB14
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa708(short *param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  FUN_8003b818((int)param_1);
  FUN_801149bc(param_1,iVar1,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aa750
 * EN v1.0 Address: 0x801AA750
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x801AAB60
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa750(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = GameBit_Get(0x1c2);
  if ((uVar1 == 0) && (uVar1 = GameBit_Get(0xa3), uVar1 != 0)) {
    iVar2 = FUN_80017a98();
    dVar4 = FUN_80017714((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
    if (dVar4 < (double)lbl_803E52FC) {
      GameBit_Set(0x1c2,1);
    }
  }
  uVar1 = GameBit_Get(0x1c3);
  if (uVar1 == 0) {
    FUN_8002fc3c((double)lbl_803E5300,(double)lbl_803DC074);
    FUN_801150ac();
    FUN_8003b280(param_1,iVar3 + 0x624);
  }
  else {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
    ObjHits_DisableObject(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aa820
 * EN v1.0 Address: 0x801AA820
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801AAC48
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa820(short *param_1,int param_2)
{
  undefined4 *puVar1;
  undefined4 local_18;
  undefined2 local_14;
  undefined4 local_10;
  undefined2 local_c;
  
  puVar1 = *(undefined4 **)(param_1 + 0x5c);
  local_10 = DAT_803e52e8;
  local_c = DAT_803e52ec;
  local_18 = DAT_803e52f0;
  local_14 = DAT_803e52f4;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  FUN_80114b10((int)param_1,puVar1,0x71c7,0x3555,3);
  dll_2E_func03((int)puVar1,600,0xf0);
  FUN_801141e8((int)puVar1,(wchar_t *)&local_18,(wchar_t *)&local_10);
  *(byte *)((int)puVar1 + 0x611) = *(byte *)((int)puVar1 + 0x611) | 10;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aa8a4
 * EN v1.0 Address: 0x801AA8A4
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801AACE8
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801aa8a4(int param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  byte bVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  if (*(char *)(param_3 + 0x8b) != '\0') {
    for (bVar2 = 0; bVar2 < *(byte *)(param_3 + 0x8b); bVar2 = bVar2 + 1) {
      bVar1 = *(byte *)(param_3 + bVar2 + 0x81);
      if (bVar1 == 2) {
        (**(code **)(*DAT_803dd718 + 0x10))
                  ((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                   (double)*(float *)(param_1 + 0x20),(double)lbl_803E5308,param_1);
      }
      else if (((bVar1 < 2) && (bVar1 != 0)) && (*(int *)(param_1 + 200) != 0)) {
        ObjLink_DetachChild(param_1,*piVar3);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801aa984
 * EN v1.0 Address: 0x801AA984
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801AADCC
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa984(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  iVar1 = *piVar2;
  if (iVar1 != 0) {
    if (*(int *)(param_9 + 200) != 0) {
      param_1 = ObjLink_DetachChild(param_9,iVar1);
    }
    if (param_10 == 0) {
      FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aaa6c
 * EN v1.0 Address: 0x801AAA6C
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801AAE2C
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aaa6c(double param_1,int param_2,int param_3)
{
  if ((double)lbl_803E530C == param_1) {
    *(undefined *)(param_2 + 0x10) = 0xc;
    return;
  }
  if ((*(byte *)(param_2 + 0x11) & 2) != 0) {
    *(undefined *)(param_2 + 0x10) = 1;
    return;
  }
  if ((double)lbl_803E5310 <= param_1) {
    *(undefined *)(param_2 + 0x10) = 2;
    return;
  }
  if ((*(short *)(param_3 + 0xa0) == 0x18) && (lbl_803E5314 < *(float *)(param_3 + 0x98))) {
    *(undefined *)(param_2 + 0x10) = 8;
    return;
  }
  if (*(short *)(param_3 + 0xa0) == 0x19) {
    *(undefined *)(param_2 + 0x10) = 5;
    return;
  }
  *(undefined *)(param_2 + 0x10) = 0xb;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aab00
 * EN v1.0 Address: 0x801AAB00
 * EN v1.0 Size: 3996b
 * EN v1.1 Address: 0x801AAEC0
 * EN v1.1 Size: 2916b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aab00(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  bool bVar1;
  short *psVar2;
  int iVar3;
  byte bVar6;
  uint uVar4;
  undefined2 *puVar5;
  float *pfVar7;
  uint *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  short unaff_r26;
  short unaff_r27;
  int unaff_r28;
  int *piVar10;
  double extraout_f1;
  double dVar11;
  double dVar12;
  double in_f31;
  double in_ps31_1;
  int local_58;
  float local_54 [5];
  undefined8 local_40;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  psVar2 = (short *)FUN_80286834();
  piVar10 = *(int **)(psVar2 + 0x5c);
  if (((&DAT_80324048)[*(byte *)(piVar10 + 4)] & 1) == 0) {
    *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) | 8;
  }
  iVar8 = piVar10[2];
  dVar11 = extraout_f1;
  if (iVar8 != 0) {
    dVar11 = FUN_8014cbcc(iVar8);
    if ((double)lbl_803E5318 < dVar11) {
      uVar4 = GameBit_Get((int)*(short *)(*(int *)(iVar8 + 0x4c) + 0x18));
      if (uVar4 == 0) {
        bVar1 = true;
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
    if (bVar1) {
      iVar8 = piVar10[3];
      dVar11 = FUN_8014cbcc(iVar8);
      if ((double)lbl_803E5318 < dVar11) {
        uVar4 = GameBit_Get((int)*(short *)(*(int *)(iVar8 + 0x4c) + 0x18));
        if (uVar4 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
      if (!bVar1) goto LAB_801ab118;
      dVar11 = FUN_80017708((float *)(piVar10[1] + 0x18),(float *)(piVar10[3] + 0x18));
      dVar12 = FUN_80017708((float *)(piVar10[1] + 0x18),(float *)(piVar10[2] + 0x18));
      if (dVar11 <= dVar12) {
        iVar8 = piVar10[3];
        iVar9 = piVar10[2];
      }
      else {
        iVar8 = piVar10[2];
        iVar9 = piVar10[3];
      }
      dVar11 = FUN_80017708((float *)(psVar2 + 0xc),(float *)(piVar10[1] + 0x18));
      if (((((double)lbl_803E531C <= dVar11) &&
           (iVar3 = FUN_80294c54(piVar10[1]), iVar3 != piVar10[2])) &&
          (iVar3 = FUN_80294c54(piVar10[1]), iVar3 != piVar10[3])) ||
         (bVar6 = FUN_80294c20(piVar10[1]), bVar6 != 0)) {
        for (bVar6 = 0; bVar6 < 2; bVar6 = bVar6 + 1) {
          dVar11 = FUN_80017708((float *)(psVar2 + 0xc),(float *)(piVar10[bVar6 + 2] + 0x18));
          local_54[bVar6] = (float)dVar11;
          FUN_8014ccac(piVar10[bVar6 + 2],psVar2);
        }
        in_f31 = (double)local_54[1];
        if (in_f31 <= (double)local_54[0]) {
          unaff_r28 = piVar10[3];
        }
        else {
          unaff_r28 = piVar10[2];
          in_f31 = (double)local_54[0];
        }
      }
      else {
        iVar3 = FUN_80294c54(piVar10[1]);
        unaff_r28 = iVar9;
        if (iVar3 == iVar9) {
          unaff_r28 = iVar8;
          iVar8 = iVar9;
        }
        FUN_8014ccac(iVar8,piVar10[1]);
        FUN_8014ccac(unaff_r28,psVar2);
        in_f31 = FUN_80017708((float *)(psVar2 + 0xc),(float *)(unaff_r28 + 0x18));
      }
    }
    else {
LAB_801ab118:
      iVar8 = piVar10[2];
      dVar11 = FUN_8014cbcc(iVar8);
      if ((double)lbl_803E5318 < dVar11) {
        uVar4 = GameBit_Get((int)*(short *)(*(int *)(iVar8 + 0x4c) + 0x18));
        if (uVar4 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
      unaff_r28 = 0;
      if (bVar1) {
        unaff_r28 = piVar10[2];
      }
      iVar8 = piVar10[3];
      dVar11 = FUN_8014cbcc(iVar8);
      if ((double)lbl_803E5318 < dVar11) {
        uVar4 = GameBit_Get((int)*(short *)(*(int *)(iVar8 + 0x4c) + 0x18));
        if (uVar4 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
      if (bVar1) {
        unaff_r28 = piVar10[3];
      }
      if (unaff_r28 == 0) {
        unaff_r28 = piVar10[1];
        in_f31 = (double)lbl_803E530C;
      }
      else {
        dVar11 = FUN_80017708((float *)(piVar10[1] + 0x18),(float *)(unaff_r28 + 0x18));
        dVar12 = FUN_80017708((float *)(psVar2 + 0xc),(float *)(unaff_r28 + 0x18));
        if (((dVar12 < dVar11) && (iVar8 = FUN_80294c54(piVar10[1]), iVar8 != unaff_r28)) ||
           (bVar6 = FUN_80294c20(piVar10[1]), bVar6 != 0)) {
          FUN_8014ccac(unaff_r28,psVar2);
        }
        else {
          FUN_8014ccac(unaff_r28,piVar10[1]);
        }
        in_f31 = FUN_80017708((float *)(psVar2 + 0xc),(float *)(unaff_r28 + 0x18));
      }
    }
    dVar11 = -(double)(*(float *)(unaff_r28 + 0xc) - *(float *)(psVar2 + 6));
    param_2 = -(double)(*(float *)(unaff_r28 + 0x14) - *(float *)(psVar2 + 10));
    iVar8 = FUN_80017730();
    unaff_r27 = (short)iVar8;
    unaff_r26 = *psVar2 - unaff_r27;
    if (0x8000 < unaff_r26) {
      unaff_r26 = unaff_r26 + 1;
    }
    if (unaff_r26 < -0x8000) {
      unaff_r26 = unaff_r26 + -1;
    }
    if (unaff_r26 < 0x1001) {
      if (unaff_r26 < -0x1000) {
        *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) | 2;
      }
      else {
        *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) & 0xfd;
      }
    }
    else {
      *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) | 2;
    }
  }
  if (*(byte *)(piVar10 + 4) < 0xc) {
    piVar10[5] = (int)((float)piVar10[5] - lbl_803DC074);
    dVar11 = (double)(float)piVar10[5];
    if (dVar11 < (double)lbl_803E5318) {
      uVar4 = randomGetRange(0xb4,300);
      local_40 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      piVar10[5] = (int)(float)(local_40 - DOUBLE_803e5338);
      dVar11 = (double)FUN_80006824((uint)psVar2,0x134);
    }
  }
  switch(*(undefined *)(piVar10 + 4)) {
  case 0:
    uVar4 = GameBit_Get(9);
    if (uVar4 == 0) {
      uVar4 = FUN_80017ae8();
      if ((uVar4 & 0xff) != 0) {
        puVar5 = FUN_80017aa4(0x20,0x6f1);
        in_r7 = *(uint **)(psVar2 + 0x18);
        iVar8 = FUN_80017ae4(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,5
                             ,0xff,0xffffffff,in_r7,in_r8,in_r9,in_r10);
        *piVar10 = iVar8;
        ObjLink_AttachChild((int)psVar2,*piVar10,0);
      }
      iVar8 = FUN_80017a98();
      piVar10[1] = iVar8;
      iVar8 = FUN_80017af8(0x45d7d);
      piVar10[2] = iVar8;
      iVar8 = FUN_80017af8(0x45d7f);
      piVar10[3] = iVar8;
      *(undefined *)(piVar10 + 4) = 1;
      uVar4 = randomGetRange(0xb4,300);
      local_40 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      piVar10[5] = (int)(float)(local_40 - DOUBLE_803e5338);
    }
    else {
      *(undefined *)(piVar10 + 4) = 0xe;
    }
    break;
  case 1:
    if ((lbl_803E5314 < *(float *)(psVar2 + 0x4c)) && (*(float *)(psVar2 + 0x4c) < lbl_803E5320)
       ) {
      if (unaff_r26 < 0x401) {
        if (unaff_r26 < -0x400) {
          local_40 = (double)(longlong)(int)(lbl_803E5324 * lbl_803DC074);
          *psVar2 = *psVar2 + (short)(int)(lbl_803E5324 * lbl_803DC074);
        }
        else {
          *psVar2 = unaff_r27;
        }
      }
      else {
        local_40 = (double)(longlong)(int)(lbl_803E5324 * lbl_803DC074);
        *psVar2 = *psVar2 - (short)(int)(lbl_803E5324 * lbl_803DC074);
      }
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      FUN_801aaa6c(in_f31,(int)piVar10,unaff_r28);
    }
    break;
  case 2:
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      if ((double)lbl_803E5310 <= in_f31) {
        *(undefined *)(piVar10 + 4) = 3;
      }
      else {
        *(undefined *)(piVar10 + 4) = 4;
      }
    }
    break;
  case 3:
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 4;
    }
    break;
  case 4:
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      FUN_801aaa6c(in_f31,(int)piVar10,unaff_r28);
    }
    break;
  case 5:
    if (*(short *)(unaff_r28 + 0xa0) != 0x19) {
      *(undefined *)(piVar10 + 4) = 7;
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 6;
    }
    break;
  case 6:
    if (*(short *)(unaff_r28 + 0xa0) != 0x19) {
      *(undefined *)(piVar10 + 4) = 7;
    }
    break;
  case 7:
    if ((*(short *)(unaff_r28 + 0xa0) != 0x18) || (*(float *)(unaff_r28 + 0x98) <= lbl_803E5314))
    {
      if (*(short *)(unaff_r28 + 0xa0) == 0x19) {
        *(undefined *)(piVar10 + 4) = 5;
      }
      else if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
        FUN_801aaa6c(in_f31,(int)piVar10,unaff_r28);
      }
    }
    else {
      *(undefined *)(piVar10 + 4) = 8;
    }
    break;
  case 8:
    bVar1 = *(short *)(unaff_r28 + 0xa0) != 0x18;
    if ((bVar1) || ((!bVar1 && (*(float *)(unaff_r28 + 0x98) < lbl_803E5314)))) {
      *(undefined *)(piVar10 + 4) = 10;
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 9;
    }
    break;
  case 9:
    bVar1 = *(short *)(unaff_r28 + 0xa0) != 0x18;
    if ((bVar1) || ((!bVar1 && (*(float *)(unaff_r28 + 0x98) < lbl_803E5314)))) {
      *(undefined *)(piVar10 + 4) = 10;
    }
    break;
  case 10:
    if ((*(short *)(unaff_r28 + 0xa0) != 0x18) || (*(float *)(unaff_r28 + 0x98) <= lbl_803E5314))
    {
      if (*(short *)(unaff_r28 + 0xa0) == 0x19) {
        *(undefined *)(piVar10 + 4) = 5;
      }
      else if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
        FUN_801aaa6c(in_f31,(int)piVar10,unaff_r28);
      }
    }
    else {
      *(undefined *)(piVar10 + 4) = 8;
    }
    break;
  case 0xb:
    FUN_801aaa6c(in_f31,(int)piVar10,unaff_r28);
    break;
  case 0xc:
    uVar4 = GameBit_Get(9);
    if (uVar4 == 0) {
      iVar8 = ObjTrigger_IsSet((int)psVar2);
      if (iVar8 == 0) {
        if ((*(byte *)((int)piVar10 + 0x11) & 2) != 0) {
          *(undefined *)(piVar10 + 4) = 0xd;
        }
      }
      else {
        GameBit_Set(9,1);
      }
    }
    else {
      uVar4 = GameBit_Get(0x24);
      if (uVar4 != 0) {
        *(undefined *)(piVar10 + 4) = 0xe;
      }
    }
    break;
  case 0xd:
    if ((lbl_803E5314 < *(float *)(psVar2 + 0x4c)) && (*(float *)(psVar2 + 0x4c) < lbl_803E5320)
       ) {
      if (unaff_r26 < 0x401) {
        if (unaff_r26 < -0x400) {
          local_40 = (double)(longlong)(int)(lbl_803E5324 * lbl_803DC074);
          *psVar2 = *psVar2 + (short)(int)(lbl_803E5324 * lbl_803DC074);
        }
        else {
          *psVar2 = unaff_r27;
        }
      }
      else {
        local_40 = (double)(longlong)(int)(lbl_803E5324 * lbl_803DC074);
        *psVar2 = *psVar2 - (short)(int)(lbl_803E5324 * lbl_803DC074);
      }
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 0xc;
    }
    break;
  case 0xe:
    if (*piVar10 != 0) {
      if (*(int *)(psVar2 + 100) != 0) {
        dVar11 = (double)ObjLink_DetachChild((int)psVar2,*piVar10);
      }
      FUN_80017ac8(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar10);
      *piVar10 = 0;
    }
    psVar2[3] = psVar2[3] | 0x4000;
    psVar2[0x58] = psVar2[0x58] | 0x8000;
    ObjHits_DisableObject((int)psVar2);
    goto LAB_801ab9cc;
  }
  if ((*(byte *)(piVar10 + 4) < 5) || (10 < *(byte *)(piVar10 + 4))) {
    pfVar7 = (float *)0x0;
    iVar8 = ObjHits_GetPriorityHit((int)psVar2,&local_58,(int *)0x0,(uint *)0x0);
    if ((iVar8 != 0) &&
       ((*(short *)(local_58 + 0x46) == 0x11 || (*(short *)(local_58 + 0x46) == 0x33)))) {
      pfVar7 = (float *)0x0;
      in_r7 = (uint *)0x0;
      in_r8 = 1;
      FUN_80017a28(psVar2,0xf,200,0,0,1);
    }
  }
  else {
    pfVar7 = local_54 + 2;
    iVar8 = ObjHits_PollPriorityHitWithCooldown((int)psVar2,(float *)&DAT_803de7b8,(undefined4 *)0x0,pfVar7);
    if (iVar8 != 0) {
      dVar11 = FUN_80017708((float *)(psVar2 + 0xc),(float *)(piVar10[1] + 0x18));
      if (dVar11 < (double)lbl_803E5328) {
        in_r7 = (uint *)0x78;
        FUN_800810e8(local_54 + 2,8,0xff,0xff,0x78);
        pfVar7 = (float *)0x0;
        FUN_80081120(psVar2,local_54 + 2,4,(int *)0x0);
      }
      FUN_80006824((uint)psVar2,0x129);
    }
  }
  uVar4 = (uint)(byte)(&DAT_80324058)[*(byte *)(piVar10 + 4)];
  if (uVar4 != (int)psVar2[0x50]) {
    if (((&DAT_80324048)[*(byte *)(piVar10 + 4)] & 2) == 0) {
      FUN_800305f8((double)lbl_803E5318,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar2,uVar4,0,pfVar7,in_r7,in_r8,in_r9,in_r10);
    }
    else {
      FUN_800305f8((double)lbl_803E5330,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar2,uVar4,0,pfVar7,in_r7,in_r8,in_r9,in_r10);
    }
  }
  iVar8 = FUN_8002fc3c((double)*(float *)(&DAT_80324068 + (uint)*(byte *)(piVar10 + 4) * 4),
                       (double)lbl_803DC074);
  if (iVar8 == 0) {
    *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) & 0xfe;
  }
  else {
    *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) | 1;
  }
LAB_801ab9cc:
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aba9c
 * EN v1.0 Address: 0x801ABA9C
 * EN v1.0 Size: 528b
 * EN v1.1 Address: 0x801ABA24
 * EN v1.1 Size: 656b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aba9c(uint param_1)
{
  uint uVar1;
  int iVar2;
  char cVar3;
  byte bVar4;
  float *pfVar5;
  double dVar6;
  undefined auStack_28 [12];
  float local_1c;
  float local_18;
  float local_14;
  
  uVar1 = GameBit_Get((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1a));
  if (uVar1 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    uVar1 = GameBit_Get(0x40);
    if (uVar1 == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
    pfVar5 = *(float **)(param_1 + 0xb8);
    iVar2 = ObjTrigger_IsSet(param_1);
    if ((iVar2 != 0) && (cVar3 = FUN_80132034(), cVar3 == '\0')) {
      *pfVar5 = lbl_803E5358;
    }
    if (lbl_803E5348 < *pfVar5) {
      if ((*(byte *)(param_1 + 0xaf) & 4) == 0) {
        *pfVar5 = lbl_803E5348;
      }
      else {
        *pfVar5 = *pfVar5 - lbl_803DC074;
        FUN_8012f744(*(undefined2 *)(*(int *)(param_1 + 0x50) + 0x7c));
      }
    }
    iVar2 = FUN_80017a98();
    dVar6 = FUN_80017714((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
    if ((dVar6 < (double)lbl_803E535C) && (bVar4 = FUN_80294c20(iVar2), bVar4 != 0)) {
      FUN_80006824(param_1,0x109);
      GameBit_Set((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1a),1);
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    local_1c = lbl_803E5340;
    local_18 = lbl_803E5344;
    local_14 = lbl_803E5348;
    FUN_800810f8((double)lbl_803E534C,(double)lbl_803E5350,(double)lbl_803E5350,
                 (double)lbl_803E5354,param_1,5,5,2,0x19,(int)auStack_28,0);
    local_1c = lbl_803E5344;
    FUN_800810f8((double)lbl_803E534C,(double)lbl_803E5350,(double)lbl_803E5350,
                 (double)lbl_803E5354,param_1,5,5,2,0x19,(int)auStack_28,0);
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    local_1c = lbl_803E5340;
    local_18 = lbl_803E5344;
    local_14 = lbl_803E5348;
    FUN_800810f8((double)lbl_803E534C,(double)lbl_803E5350,(double)lbl_803E5350,
                 (double)lbl_803E5354,param_1,5,2,2,0x19,(int)auStack_28,0);
    local_1c = lbl_803E5344;
    FUN_800810f8((double)lbl_803E534C,(double)lbl_803E5350,(double)lbl_803E5350,
                 (double)lbl_803E5354,param_1,5,2,2,0x19,(int)auStack_28,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801abcac
 * EN v1.0 Address: 0x801ABCAC
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x801ABCB4
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801abcac(int param_1,int param_2)
{
  bool bVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = GameBit_Get((int)*(short *)(param_2 + 4));
  if (uVar2 != 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_80017a78(param_1,1);
    return;
  }
  FUN_80017a78(param_1,0);
  uVar2 = GameBit_Get(0xa9);
  if (uVar2 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    iVar3 = ObjTrigger_IsSetById(param_1,0xa9);
    if (iVar3 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      FUN_80017680(0xa9);
      bVar1 = true;
      goto LAB_801abd84;
    }
  }
  bVar1 = false;
LAB_801abd84:
  if (bVar1) {
    *(byte *)(param_2 + 6) = *(byte *)(param_2 + 6) | 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801abda4
 * EN v1.0 Address: 0x801ABDA4
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801ABDB4
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801abda4(int param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  uVar1 = GameBit_Get(0xdc5);
  if (uVar1 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  uVar1 = GameBit_Get((int)*(short *)(param_2 + 4));
  if (uVar1 == 0) {
    FUN_80017a78(param_1,1);
    iVar2 = ObjTrigger_IsSet(param_1);
    if (iVar2 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
      FUN_80017688(0xa9);
      *(byte *)(param_2 + 6) = *(byte *)(param_2 + 6) | 1;
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_80017a78(param_1,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801abe84
 * EN v1.0 Address: 0x801ABE84
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x801ABEB4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801abe84(int param_1)
{
  uint uVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0xb8);
  if (*(byte *)((int)puVar2 + 6) != 0) {
    if ((*(byte *)((int)puVar2 + 6) & 1) == 0) {
      GameBit_Set((int)*(short *)(puVar2 + 1),0);
    }
    else {
      GameBit_Set((int)*(short *)(puVar2 + 1),1);
    }
    *(undefined *)((int)puVar2 + 6) = 0;
    uVar1 = GameBit_Get(0xdf0);
    if ((uVar1 == 0) && (uVar1 = GameBit_Get(0xaa), uVar1 != 0)) {
      GameBit_Set(0xdf0,1);
    }
  }
  (*(code *)*puVar2)(param_1,puVar2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801abf34
 * EN v1.0 Address: 0x801ABF34
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801ABF64
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801abf34(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801abf38
 * EN v1.0 Address: 0x801ABF38
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x801AC038
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801abf38(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,int param_11)
{
  if (*(char *)(param_11 + 0x8b) != '\0') {
    FUN_8008112c((double)lbl_803E5360,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,1,1,0,1,1,1,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801abfec
 * EN v1.0 Address: 0x801ABFEC
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801AC090
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801abfec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  FUN_80080f14(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
  FUN_800067c0((int *)0xc8,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ac040
 * EN v1.0 Address: 0x801AC040
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801AC0C0
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ac040(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ac060
 * EN v1.0 Address: 0x801AC060
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AC0E4
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ac060(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/* 8b "li r3, N; blr" returners. */
int cclightfoot_getExtraSize(void) { return 0x18; }
int ccsharpclawpad_getExtraSize(void) { return 0x4; }
int ccpedstal_getExtraSize(void) { return 0x8; }
int cclevcontrol_getExtraSize(void) { return 0x10; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E46CC;
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void cclevcontrol_render(void) { objRenderFn_8003b8f4(lbl_803E46CC); }
#pragma peephole reset
#pragma scheduling reset

/* Drift-recovery: add new fns with v1.0 names. */
extern void envFxActFn_800887f8(int a);
extern void Music_Trigger(int a, int b);
extern void spawnExplosion(f32 size, int a, int b, int c, int d, int e, int f, int g);
extern int fn_801AA734(int obj, int unused, u8* data);
extern f32 lbl_803E46C8;

#pragma scheduling off
#pragma peephole off

void ccsharpclawpad_init(int* obj, int* def)
{
    *(s16*)obj = (s16)((u32)*(u8*)((char*)def + 24) << 8);
    *(u16*)((char*)obj + 176) = (u16)(*(u16*)((char*)obj + 176) | 0x4000);
}

void cclevcontrol_free(void)
{
    envFxActFn_800887f8(0);
    Music_Trigger(200, 0);
}

void cclightfoot_init(int* obj, int* def)
{
    *(s16*)obj = (s16)((u32)*(u8*)((char*)def + 26) << 8);
    *(u16*)((char*)obj + 176) = (u16)(*(u16*)((char*)obj + 176) | 0x4000);
    *(void**)((char*)obj + 188) = (void*)fn_801AA734;
}

int fn_801ABA84(int p1, int p2, u8* state)
{
    if (state[139] != 0) {
        spawnExplosion(lbl_803E46C8, 1, 1, 0, 1, 1, 1, 0);
    }
    return 0;
}

/* ObjLink_DetachChild and Obj_FreeObject already declared in earlier extern blocks */

void cclightfoot_free(int* obj, int p2)
{
    int* state = *(int**)((char*)obj + 0xb8);
    int* sub = (int*)state[0];
    if (sub != NULL) {
        if (*(void**)((char*)obj + 200) != NULL) {
            ObjLink_DetachChild(obj, sub);
        }
        if (p2 == 0) {
            Obj_FreeObject((int*)state[0]);
        }
    }
}

extern void fn_80088870(void *a, void *b, void *c, void *d);
extern int getSaveGameLoadStatus(void);
extern void getEnvfxActImmediately(void *obj, void *target, int animId, int flags);
extern void getEnvfxAct(int obj, int target, int id, int p);
extern int *gMapEventInterface;
extern int lbl_80323548[];
extern f32 lbl_803E46D4;
extern void fn_801AB700(int obj, u8* state2);
extern void fn_801AB800(int obj, u8* state2);
extern void fn_8002B6D8(void *obj, int p2, int p3, int p4, int p5, int p6);

void ccpedstal_init(int *obj, u8 *params) {
    u8 *state = *(u8 **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((u32)params[0x1a] << 8);
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x4000);
    switch (*(int *)(params + 0x14)) {
    case 0x45f1a:
        *(void **)state = (void *)fn_801AB800;
        *(s16 *)(state + 4) = 0xaa;
        fn_8002B6D8(obj, 0, 0, 0, 0, 3);
        break;
    case 0x45f1b:
        *(void **)state = (void *)fn_801AB700;
        *(s16 *)(state + 4) = 0xf1;
        break;
    case 0x45f1c:
        *(void **)state = (void *)fn_801AB700;
        *(s16 *)(state + 4) = 0xfe;
        break;
    }
}

void cclevcontrol_init(int *obj) {
    int *state;
    state = *(int **)((char *)obj + 0xb8);
    *(void **)((char *)obj + 0xbc) = (void *)fn_801ABA84;
    fn_80088870((char *)lbl_80323548 + 0x38, lbl_80323548, (char *)lbl_80323548 + 0x70, (char *)lbl_80323548 + 0xa8);
    if (getSaveGameLoadStatus() != 0) {
        envFxActFn_800887f8(0x3f);
        getEnvfxActImmediately((void *)0, (void *)0, 0x242, 0);
    } else {
        envFxActFn_800887f8(0x1f);
        getEnvfxAct(0, 0, 0x242, 0);
    }
    *(f32 *)state = lbl_803E46D4;
    state[2] = -1;
    state[3] = (u32)(u8)((int (*)(int))((int **)*gMapEventInterface)[0x10])(((s8 *)obj)[0xac]);
}

#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E4674;
extern f32 lbl_803E4678;
extern f32 lbl_803E467C;

#pragma scheduling off
#pragma peephole off
void fn_801AA878(u8* p1, int* p2, f32 v) {
    s16 t;
    if (lbl_803E4674 == v) {
        p1[16] = 12;
        return;
    }
    if ((p1[17] & 2) != 0) {
        p1[16] = 1;
        return;
    }
    if (v < lbl_803E4678) {
        t = *(s16*)((char*)p2 + 160);
        if (t == 24 && *(f32*)((char*)p2 + 152) > lbl_803E467C) {
            p1[16] = 8;
            return;
        }
        if (t == 25) {
            p1[16] = 5;
            return;
        }
        p1[16] = 11;
        return;
    }
    p1[16] = 2;
}
#pragma peephole reset
#pragma scheduling reset

extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void gameBitDecrement(int id);
extern int** gObjectTriggerInterface;

/* fn_801AB700: state2-driven model + trigger gate. If state2's gamebit at
 * +0x4 is set, latches obj[0xaf] bit 8 and selects model index 1.
 * Otherwise selects model 0, then consults gbit 0xa9: if set, clears the
 * 0x10 flag and (if the obj's trigger 0xa9 is set) fires vtable[0x12],
 * decrements the gamebit, and flags state2[0x6] bit 0. If gbit 0xa9 is
 * clear, sets the obj[0xaf] 0x10 flag instead. */
#pragma scheduling off
#pragma peephole off
void fn_801AB700(int obj, u8* state2) {
    if (GameBit_Get(*(s16*)(state2 + 0x4)) != 0) {
        *(u8*)(obj + 0xaf) = (u8)(*(u8*)(obj + 0xaf) | 8);
        Obj_SetActiveModelIndex(obj, 1);
    } else {
        int doMark;
        Obj_SetActiveModelIndex(obj, 0);
        if (GameBit_Get(0xa9) != 0) {
            *(u8*)(obj + 0xaf) = (u8)(*(u8*)(obj + 0xaf) & ~0x10);
            if (ObjTrigger_IsSetById(obj, 0xa9) != 0) {
                (*(void(**)(int, int, int))(*(int*)gObjectTriggerInterface + 0x48))(0, obj, -1);
                gameBitDecrement(0xa9);
                doMark = 1;
                goto check;
            }
        } else {
            *(u8*)(obj + 0xaf) = (u8)(*(u8*)(obj + 0xaf) | 0x10);
        }
        doMark = 0;
    check:
        if (doMark != 0) {
            state2[0x6] = (u8)(state2[0x6] | 1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int ObjTrigger_IsSet(int obj);
extern void gameBitIncrement(int id);

/* fn_801AB800: ccpedstal alt-variant think-routine. Toggles obj[0xaf]
 * bit 8 from gbit 0xdc5, then reads state2's gamebit at +0x4: if set,
 * sets bit 8 again and selects model 0; if clear, selects model 1 and
 * (when the obj's pending trigger is asserted) fires vtable[0x12] with
 * id=1, increments gbit 0xa9, and latches state2[0x6] bit 0. Mirrors
 * the no-mark branches into a shared r0=0/cmpwi end-check via goto to
 * match target's layout. */
#pragma scheduling off
#pragma peephole off
void fn_801AB800(int obj, u8* state2) {
    if (GameBit_Get(0xdc5) != 0) {
        *(u8*)(obj + 0xaf) = (u8)(*(u8*)(obj + 0xaf) | 8);
    } else {
        *(u8*)(obj + 0xaf) = (u8)(*(u8*)(obj + 0xaf) & ~8);
    }
    if (GameBit_Get(*(s16*)(state2 + 0x4)) != 0) {
        *(u8*)(obj + 0xaf) = (u8)(*(u8*)(obj + 0xaf) | 8);
        Obj_SetActiveModelIndex(obj, 0);
    } else {
        int doMark;
        Obj_SetActiveModelIndex(obj, 1);
        if (ObjTrigger_IsSet(obj) != 0) {
            (*(void(**)(int, int, int))(*(int*)gObjectTriggerInterface + 0x48))(1, obj, -1);
            gameBitIncrement(0xa9);
            doMark = 1;
            goto check;
        }
        doMark = 0;
    check:
        if (doMark != 0) {
            state2[0x6] = (u8)(state2[0x6] | 1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int* gWaterfxInterface;
extern f32 lbl_803E4670;

extern void dll_2E_func05(int *obj, u8 *sub, int a, int b, int c);
extern void dll_2E_func08(u8 *sub, int a, int b);
extern void dll_2E_func09(u8 *sub, void *a, void *b, int c);

typedef struct { s16 v[3]; } _S16x3;
extern _S16x3 lbl_803E4650;
extern _S16x3 lbl_803E4658;

#pragma scheduling off
#pragma peephole off
void ccqueen_init(int *obj, u8 *init) {
    u8 *sub;
    _S16x3 buf1;
    _S16x3 buf2;
    sub = *(u8**)((char*)obj + 0xb8);
    buf2 = lbl_803E4650;
    buf1 = lbl_803E4658;
    *(s16*)obj = (s16)(init[0x1a] << 8);
    dll_2E_func05(obj, sub, 0x71c7, 0x3555, 3);
    dll_2E_func08(sub, 0x258, 0xf0);
    dll_2E_func09(sub, &buf1, &buf2, 3);
    sub[0x611] = (u8)(sub[0x611] | 0xa);
}
#pragma peephole reset
#pragma scheduling reset
extern f32 lbl_803E4664;
extern f32 lbl_803E4668;
extern f32 timeDelta;
extern uint GameBit_Get(int eventId);
extern unsigned long GameBit_Set(int eventId, int value);
extern f32 vec3f_distanceSquared(f32* p1, f32* p2);
extern void ObjAnim_AdvanceCurrentMove(void* obj, int flag, f32 weight, f32 dt);
extern void characterDoEyeAnims(int obj, void* p);
extern void *Obj_GetPlayerObject(void);
extern void ObjHits_DisableObject_xx(int *obj);

#pragma scheduling off
#pragma peephole off
void ccqueen_update(int *obj) {
    u8 *sub;
    int *player;

    sub = *(u8**)((char*)obj + 0xb8);
    if (GameBit_Get(0x1c2) == 0 && GameBit_Get(0xa3) != 0) {
        player = (int*)Obj_GetPlayerObject();
        if (vec3f_distanceSquared((f32*)((char*)obj + 0x18), (f32*)((char*)player + 0x18)) < lbl_803E4664) {
            GameBit_Set(0x1c2, 1);
        }
    }
    if (GameBit_Get(0x1c3) != 0) {
        *(s16*)((char*)obj + 6) = (s16)(*(s16*)((char*)obj + 6) | 0x4000);
        *(u16*)((char*)obj + 0xb0) = (u16)(*(u16*)((char*)obj + 0xb0) | 0x8000);
        ObjHits_DisableObject(obj);
    } else {
        ObjAnim_AdvanceCurrentMove(obj, 0, lbl_803E4668, timeDelta);
        dll_2E_func03(obj, sub);
        characterDoEyeAnims((int)obj, sub + 0x624);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* fn_801AA734: ccqueen seqFn dispatcher. Walks the (u8)data[0x8b] command
 * bytes at data[0x81..]: cmd=1 detaches obj's child via ObjLink_DetachChild
 * (only when obj->_c8 != 0); cmd=2 dispatches gWaterfxInterface vtable[4]
 * with the obj's xyz position and lbl_803E4670 as a 5-arg call. Returns 0. */
#pragma scheduling off
#pragma peephole off
int fn_801AA734(int obj, int unused, u8* data) {
    int* state = *(int**)(obj + 0xb8);
    if (data[0x8b] != 0) {
        u8 i;
        for (i = 0; (u32)i < (u32)data[0x8b]; i++) {
            int cmd = data[0x81 + (u32)i];
            switch (cmd) {
            case 1:
                if (*(int*)(obj + 0xc8) != 0) {
                    ObjLink_DetachChild(obj, *(int*)state);
                }
                break;
            case 2:
                ((void(*)(int, f32, f32, f32, f32))((void**)*gWaterfxInterface)[4])(
                    obj,
                    *(f32*)(obj + 0x18),
                    *(f32*)(obj + 0x1c),
                    *(f32*)(obj + 0x20),
                    lbl_803E4670);
                break;
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
