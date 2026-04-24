#include "ghidra_import.h"
#include "main/dll/SC/SCchieflightfoot.h"

extern undefined4 FUN_8000bb38();
extern double FUN_80021730();
extern int FUN_80021884();
extern uint FUN_80022264();
extern int FUN_8002fb40();
extern undefined4 FUN_8003042c();
extern char objHitReact_update();
extern int FUN_8003811c();
extern undefined4 FUN_80038524();
extern undefined4 FUN_8003b320();
extern undefined4 FUN_8003b408();
extern int FUN_8005a288();
extern undefined4 FUN_8006f0b4();
extern undefined4 FUN_80115330();
extern undefined4 FUN_801d5afc();
extern undefined4 FUN_801d5cb4();
extern undefined4 FUN_801d5ed4();
extern undefined4 FUN_801d6158();
extern undefined4 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();

extern undefined DAT_80327b78;
extern undefined DAT_80327d6c;
extern undefined4 DAT_80327f60;
extern undefined4 DAT_80327f84;
extern undefined4 DAT_80327fc8;
extern undefined4 DAT_80327fdc;
extern undefined4 DAT_80328000;
extern undefined4 DAT_803dcc60;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e60c0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e60b0;
extern f32 FLOAT_803e60e0;
extern f32 FLOAT_803e60e4;
extern f32 FLOAT_803e60e8;

/*
 * --INFO--
 *
 * Function: SHthorntail_update
 * EN v1.0 Address: 0x801D5F58
 * EN v1.0 Size: 2280b
 * EN v1.1 Address: 0x801D6548
 * EN v1.1 Size: 1928b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                        undefined8 param_5,undefined8 param_6,undefined8 param_7,
                        undefined8 param_8)
{
  byte bVar1;
  short *psVar2;
  char cVar3;
  undefined uVar4;
  undefined *puVar5;
  int iVar6;
  uint uVar7;
  float *pfVar8;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar9;
  int iVar10;
  double extraout_f1;
  double dVar11;
  double extraout_f1_00;
  double dVar12;
  double in_f31;
  double in_ps31_1;
  undefined auStack_78 [12];
  float fStack_6c;
  undefined4 uStack_68;
  float fStack_64;
  float local_60 [2];
  float local_58;
  short local_52;
  char local_4d [8];
  char local_45;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  psVar2 = (short *)FUN_8028683c();
  iVar10 = *(int *)(psVar2 + 0x5c);
  iVar9 = *(int *)(psVar2 + 0x26);
  dVar11 = extraout_f1;
  if (*(char *)(iVar10 + 0x624) == '\f') {
    if (*(float *)(iVar10 + 0x638) <= FLOAT_803e60b0) {
      if ((psVar2[0x58] & 0x800U) != 0) {
        FUN_80038524(psVar2,4,&fStack_6c,&uStack_68,&fStack_64,0);
        in_r8 = 0;
        in_r9 = *DAT_803dd708;
        (**(code **)(in_r9 + 8))(psVar2,0x7f0,auStack_78,0x200001,0xffffffff);
      }
      *(float *)(iVar10 + 0x638) = FLOAT_803e60e8;
    }
    dVar11 = (double)*(float *)(iVar10 + 0x638);
    *(float *)(iVar10 + 0x638) = (float)(dVar11 - (double)FLOAT_803dc074);
  }
  *(byte *)(iVar10 + 0x625) = *(byte *)(iVar10 + 0x625) & 0xf7;
  if (((&DAT_80327fc8)[*(char *)(iVar10 + 0x624)] & 2) == 0) {
    puVar5 = &DAT_80327b78;
  }
  else {
    puVar5 = &DAT_80327d6c;
  }
  iVar6 = 0x19;
  uVar7 = (uint)*(byte *)(iVar10 + 0x640);
  pfVar8 = (float *)(iVar10 + 0x8ac);
  cVar3 =
      objHitReact_update(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,
                         puVar5,0x19,uVar7,pfVar8,in_r8,in_r9,in_r10);
  *(char *)(iVar10 + 0x640) = cVar3;
  if (cVar3 == '\0') {
    uVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(psVar2 + 0x56));
    *(undefined *)(iVar10 + 0x626) = uVar4;
    bVar1 = *(byte *)(iVar9 + 0x18);
    if (bVar1 == 2) {
      FUN_801d5cb4(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,
                   iVar10,iVar6,uVar7,pfVar8,in_r8,in_r9,in_r10);
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        FUN_801d6158(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,
                     iVar10,iVar9,uVar7,pfVar8,in_r8,in_r9,in_r10);
      }
      else {
        FUN_801d5ed4((uint)psVar2,iVar10,iVar9);
      }
    }
    else if (bVar1 < 4) {
      FUN_801d5afc(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,
                   iVar10,iVar6,uVar7,pfVar8,in_r8,in_r9,in_r10);
    }
    if (((&DAT_80327fc8)[*(char *)(iVar10 + 0x624)] & 1) == 0) {
      *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) & 0xef;
      *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) & 0xf7;
    }
    else {
      *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) | 0x10;
    }
    if ((*(byte *)(iVar10 + 0x625) & 0x10) != 0) {
      bVar1 = *(char *)(iVar10 + 0x63f) + 1;
      *(byte *)(iVar10 + 0x63f) = bVar1;
      if (bVar1 < 0xb) {
        *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) | 8;
      }
      else {
        *(byte *)(iVar10 + 0x625) = *(byte *)(iVar10 + 0x625) & 0xef;
      }
    }
    if ((int)psVar2[0x50] != (int)*(short *)(&DAT_80327f60 + *(char *)(iVar10 + 0x624) * 2)) {
      FUN_8003042c((double)FLOAT_803e60b0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar2,(int)*(short *)(&DAT_80327f60 + *(char *)(iVar10 + 0x624) * 2),0,uVar7,
                   pfVar8,in_r8,in_r9,in_r10);
      *(short *)(iVar10 + 0x63c) = *psVar2;
    }
    iVar6 = FUN_8002fb40((double)*(float *)(&DAT_80327f84 + *(char *)(iVar10 + 0x624) * 4),
                         (double)FLOAT_803dc074);
    if (iVar6 == 0) {
      *(byte *)(iVar10 + 0x625) = *(byte *)(iVar10 + 0x625) & 0xfe;
    }
    else {
      *(byte *)(iVar10 + 0x625) = *(byte *)(iVar10 + 0x625) | 1;
    }
    if (((&DAT_80327fc8)[*(char *)(iVar10 + 0x624)] & 8) != 0) {
      if ((*(byte *)(iVar10 + 0x625) & 1) != 0) {
        *(short *)(iVar10 + 0x63c) = *psVar2;
      }
      uStack_3c = (int)*(short *)(iVar10 + 0x63c) ^ 0x80000000;
      local_40 = 0x43300000;
      dVar11 = (double)FUN_802945e0();
      dVar11 = -dVar11;
      uStack_34 = (int)*(short *)(iVar10 + 0x63c) ^ 0x80000000;
      local_38 = 0x43300000;
      dVar12 = (double)FUN_80294964();
      *(float *)(psVar2 + 6) = (float)(dVar11 * -(double)local_58 + (double)*(float *)(psVar2 + 6));
      *(float *)(psVar2 + 10) =
           (float)(-dVar12 * -(double)local_58 + (double)*(float *)(psVar2 + 10));
      *(float *)(psVar2 + 6) =
           (float)(-dVar12 * -(double)local_60[0] + (double)*(float *)(psVar2 + 6));
      *(float *)(psVar2 + 10) =
           (float)(dVar11 * (double)local_60[0] + (double)*(float *)(psVar2 + 10));
      *psVar2 = *psVar2 + local_52;
    }
    pfVar8 = local_60;
    for (iVar6 = 0; iVar6 < local_45; iVar6 = iVar6 + 1) {
      if (*(char *)((int)pfVar8 + 0x13) == '\0') {
        if (*(ushort *)(&DAT_80327fdc + *(char *)(iVar10 + 0x624) * 2) != 0) {
          FUN_8000bb38((uint)psVar2,*(ushort *)(&DAT_80327fdc + *(char *)(iVar10 + 0x624) * 2));
        }
      }
      else if ((*(char *)((int)pfVar8 + 0x13) == '\a') &&
              ((&DAT_80328000)[*(char *)(iVar10 + 0x624)] != 0)) {
        FUN_8000bb38((uint)psVar2,(ushort)(byte)(&DAT_80328000)[*(char *)(iVar10 + 0x624)]);
      }
      pfVar8 = (float *)((int)pfVar8 + 1);
    }
    FUN_8006f0b4((double)FLOAT_803e60e0,(double)FLOAT_803e60e0,psVar2,local_60,8,iVar10 + 0x8e0,
                 iVar10 + 0x644);
    if (((&DAT_80327fc8)[*(char *)(iVar10 + 0x624)] & 4) == 0) {
      *(byte *)(iVar10 + 0x611) = *(byte *)(iVar10 + 0x611) | 1;
    }
    else {
      *(byte *)(iVar10 + 0x611) = *(byte *)(iVar10 + 0x611) & 0xfe;
    }
    FUN_80115330();
    if (((&DAT_80327fc8)[*(char *)(iVar10 + 0x624)] & 2) == 0) {
      FUN_8003b408((int)psVar2,iVar10 + 0x8b0);
    }
    else {
      FUN_8003b320((int)psVar2,iVar10 + 0x8b0);
    }
    *(byte *)(iVar10 + 0x625) = *(byte *)(iVar10 + 0x625) & 0xfd;
    if (((*(byte *)(iVar10 + 0x625) & 4) == 0) && (iVar6 = FUN_8003811c((int)psVar2), iVar6 != 0)) {
      uVar7 = FUN_80022264(1,(uint)**(byte **)(iVar10 + 0x62c));
      *(byte *)(iVar10 + 0x625) = *(byte *)(iVar10 + 0x625) | 2;
      (**(code **)(*DAT_803dd6d4 + 0x48))
                (*(undefined *)(*(int *)(iVar10 + 0x62c) + uVar7),psVar2,0xffffffff);
    }
    if (*(char *)(iVar9 + 0x1b) != '\0') {
      dVar11 = FUN_80021730((float *)(psVar2 + 0xc),(float *)(iVar9 + 8));
      uStack_34 = (uint)*(byte *)(iVar9 + 0x1b) * (uint)*(byte *)(iVar9 + 0x1b) ^ 0x80000000;
      local_38 = 0x43300000;
      if (((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e60c0) < dVar11) &&
         (iVar9 = FUN_8005a288((double)(*(float *)(psVar2 + 0x54) * *(float *)(psVar2 + 4)),
                               (float *)(psVar2 + 6)), iVar9 == 0)) {
        iVar9 = FUN_80021884();
        *psVar2 = (short)iVar9;
      }
    }
    *(undefined *)(iVar10 + 0x89f) = 1;
    if (DAT_803dcc60 == -1) {
      DAT_803dcc60 = *(int *)(*(int *)(psVar2 + 0x26) + 0x14);
      *(float *)(psVar2 + 0x14) = -(FLOAT_803e60e4 * FLOAT_803dc074 - *(float *)(psVar2 + 0x14));
      (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,psVar2,iVar10 + 0x644);
      (**(code **)(*DAT_803dd728 + 0x14))(psVar2,iVar10 + 0x644);
      (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,psVar2,iVar10 + 0x644);
      psVar2[1] = *(short *)(iVar10 + 0x7dc);
      psVar2[2] = *(short *)(iVar10 + 0x7de);
    }
    else {
      if (DAT_803dcc60 == *(int *)(*(int *)(psVar2 + 0x26) + 0x14)) {
        DAT_803dcc60 = -1;
      }
      if ((*(char *)(iVar10 + 0x624) < '\x02') || ('\x06' < *(char *)(iVar10 + 0x624))) {
        (**(code **)(*DAT_803dd728 + 0x20))(psVar2,iVar10 + 0x644);
      }
      else {
        *(float *)(psVar2 + 0x14) = -(FLOAT_803e60e4 * FLOAT_803dc074 - *(float *)(psVar2 + 0x14));
        (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,psVar2,iVar10 + 0x644);
        (**(code **)(*DAT_803dd728 + 0x14))(psVar2,iVar10 + 0x644);
        (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,psVar2,iVar10 + 0x644);
        psVar2[1] = *(short *)(iVar10 + 0x7dc);
        psVar2[2] = *(short *)(iVar10 + 0x7de);
      }
    }
  }
  FUN_80286888();
  return;
}
