#include "ghidra_import.h"
#include "main/expgfx.h"

extern undefined4 ABS();
extern int FUN_80008b4c();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000dd94();
extern undefined4 FUN_8000f554();
extern undefined4 FUN_8000f56c();
extern undefined4 FUN_8000f7a0();
extern undefined4 FUN_8000f85c();
extern void* FUN_8000facc();
extern undefined4 FUN_8000fb14();
extern int FUN_80020800();
extern int FUN_80021884();
extern undefined4 FUN_80021b8c();
extern uint FUN_80022264();
extern undefined4 FUN_80022a0c();
extern undefined4 FUN_80022a88();
extern undefined4 FUN_80022abc();
extern uint FUN_80022b0c();
extern int FUN_8002ba84();
extern int FUN_8002bac4();
extern undefined4 FUN_8004c460();
extern undefined8 FUN_80054484();
extern int FUN_8005b128();
extern undefined4 FUN_8005d264();
extern undefined4 FUN_8005e010();
extern uint FUN_8005eaf8();
extern undefined4 FUN_80070434();
extern undefined4 FUN_8007048c();
extern undefined4 FUN_80070540();
extern undefined4 FUN_800792fc();
extern undefined4 FUN_8007986c();
extern undefined4 FUN_80079980();
extern undefined4 FUN_80079b3c();
extern undefined4 FUN_8007c54c();
extern undefined4 FUN_8007d7ec();
extern int FUN_800892bc();
extern undefined4 FUN_80089a60();
extern undefined4 FUN_80089b54();
extern undefined4 FUN_8009afd0();
extern int FUN_8009b078();
extern undefined8 FUN_80137c30();
extern double FUN_80139300();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_802475e4();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80247ef8();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80259000();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d888();
extern undefined8 FUN_8028680c();
extern undefined8 FUN_80286824();
extern int FUN_80286828();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286858();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80293674();
extern double FUN_80293900();
extern double FUN_8029686c();

extern undefined4 DAT_80310458;
extern undefined2 DAT_80310488;
extern undefined DAT_80310528;
extern undefined2 DAT_803105a8;
extern undefined4 DAT_80397420;
extern int DAT_8039b7b8;
extern undefined4 DAT_8039b9b8;
extern undefined4 DAT_8039b9bc;
extern undefined4 DAT_8039b9c0;
extern undefined4 DAT_8039b9c4;
extern undefined4 DAT_8039b9c8;
extern undefined4 DAT_8039b9cc;
extern int DAT_8039c138;
extern undefined4 DAT_8039c13c;
extern undefined4 DAT_8039c140;
extern short DAT_8039c144;
extern undefined4 DAT_8039c146;
extern byte DAT_8039c638;
extern int DAT_8039c688;
extern undefined4 DAT_8039c7c8;
extern undefined4 DAT_8039c7cc;
extern byte DAT_8039c7d8;
extern char DAT_8039c828;
extern char DAT_8039c829;
extern uint DAT_8039c878;
extern uint DAT_8039c9b8;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dd430;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd718;
extern undefined4 DAT_803dded0;
extern undefined4 DAT_803dded2;
extern undefined4 DAT_803dded4;
extern undefined4 DAT_803dded8;
extern undefined4 DAT_803ddee8;
extern undefined4 DAT_803ddeea;
extern undefined4 DAT_803ddeec;
extern undefined4 DAT_803ddef0;
extern undefined4 DAT_803ddef4;
extern undefined4 DAT_803ddef8;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803dffe0;
extern f64 DOUBLE_803dfff8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc3f0;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803ddedc;
extern f32 FLOAT_803ddee0;
extern f32 FLOAT_803ddee4;
extern f32 FLOAT_803dffd0;
extern f32 FLOAT_803dffd4;
extern f32 FLOAT_803dffd8;
extern f32 FLOAT_803dffdc;
extern f32 FLOAT_803e0004;
extern f32 FLOAT_803e000c;
extern f32 FLOAT_803e0010;
extern f32 FLOAT_803e0030;
extern f32 FLOAT_803e0034;
extern f32 FLOAT_803e0038;
extern f32 FLOAT_803e003c;
extern f32 FLOAT_803e0040;
extern f32 FLOAT_803e0044;
extern f32 FLOAT_803e0048;
extern f32 FLOAT_803e004c;
extern f32 FLOAT_803e0050;
extern f32 FLOAT_803e0054;
extern f32 FLOAT_803e0058;
extern f32 FLOAT_803e005c;
extern f32 FLOAT_803e0060;
extern f32 FLOAT_803e0064;
extern f32 FLOAT_803e0068;
extern f32 FLOAT_803e006c;
extern f32 FLOAT_803e0070;
extern f32 FLOAT_803e0074;
extern f32 FLOAT_803e0078;
extern f32 FLOAT_803e007c;
extern f32 FLOAT_803e0080;
extern f32 FLOAT_803e0084;
extern f32 FLOAT_803e0088;
extern f32 FLOAT_803e008c;
extern f32 FLOAT_803e0090;
extern f32 FLOAT_803e0094;
extern f32 FLOAT_803e0098;
extern f32 FLOAT_803e009c;
extern f32 FLOAT_803e00a0;
extern f32 FLOAT_803e00a4;
extern f32 FLOAT_803e00a8;
extern char s_expgfx_c__addToTable_usage_overf_803107e8[];
extern char s_expgfx_c__exptab_is_FULL_80310810[];
extern char s_expgfx_c__invalid_tabindex_8031082c[];
extern char s_expgfx_c__mismatch_in_add_remove_803107b0[];
extern char s_expgfx_c__scale_overflow_80310848[];
extern char s_notexture_803107dc[];

/*
 * --INFO--
 *
 * Function: FUN_8009b36c
 * EN v1.0 Address: 0x8009B36C
 * EN v1.0 Size: 372b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009b36c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  short *psVar3;
  char *pcVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  
  uVar8 = FUN_80286838();
  iVar2 = (int)uVar8;
  puVar7 = &DAT_8039c878 + iVar2;
  if ((1 << param_11 & *puVar7) != 0) {
    uVar6 = (int)((ulonglong)uVar8 >> 0x20) + param_11 * 0xa0;
    *(undefined4 *)(uVar6 + 0x7c) = 0;
    if (param_12 == 0) {
      uVar5 = param_13;
      uVar8 = extraout_f1;
      if ((&DAT_8039c140)[(uint)(*(byte *)(uVar6 + 0x8a) >> 1) * 4] != 0) {
        DAT_803dded8 = 1;
        uVar8 = FUN_80054484();
        DAT_803dded8 = 0;
      }
      uVar1 = (uint)(*(byte *)(uVar6 + 0x8a) >> 1);
      psVar3 = &DAT_8039c144 + uVar1 * 8;
      if (*psVar3 == 0) {
        FUN_80137c30(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     s_expgfx_c__mismatch_in_add_remove_803107b0,psVar3,uVar1 * 0x10,param_12,uVar5,
                     param_14,param_15,param_16);
      }
      else {
        *psVar3 = *psVar3 + -1;
        if (*psVar3 == 0) {
          (&DAT_8039c140)[uVar1 * 4] = 0;
          (&DAT_8039c138)[uVar1 * 4] = 0;
        }
      }
    }
    *(undefined2 *)(uVar6 + 0x26) = 0xffff;
    if ((param_13 & 0xff) != 0) {
      FUN_802420e0(uVar6,0xa0);
    }
    *puVar7 = *puVar7 & ~(1 << param_11);
    pcVar4 = &DAT_8039c828 + iVar2;
    *pcVar4 = *pcVar4 + -1;
    if (*pcVar4 == '\0') {
      (&DAT_80310488)[iVar2] = 0xffff;
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8009b4e0
 * EN v1.0 Address: 0x8009B4E0
 * EN v1.0 Size: 360b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009b4e0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8009b648
 * EN v1.0 Address: 0x8009B648
 * EN v1.0 Size: 792b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8009b648(short *param_1,undefined2 *param_2,short param_3,int param_4,int param_5)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8009b960
 * EN v1.0 Address: 0x8009B960
 * EN v1.0 Size: 756b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009b960(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
  double dVar1;
  undefined2 *puVar2;
  uint uVar3;
  undefined2 uVar4;
  int iVar5;
  undefined2 uVar6;
  undefined4 in_r8;
  undefined2 uVar7;
  undefined4 in_r9;
  undefined2 uVar8;
  undefined4 in_r10;
  double dVar9;
  double dVar10;
  undefined8 local_18;
  undefined8 local_8;
  
  iVar5 = (&DAT_8039c140)[(uint)(*(byte *)(param_9 + 0x45) >> 1) * 4];
  *(byte *)((int)param_9 + 0x8b) = *(byte *)((int)param_9 + 0x8b) & 0xfe;
  *(byte *)((int)param_9 + 0x8b) = *(byte *)((int)param_9 + 0x8b) & 0xfd | 2;
  uVar3 = *(uint *)(param_9 + 0x3e);
  if ((uVar3 & 0x8000000) == 0) {
    puVar2 = (undefined2 *)0x803105c0;
  }
  else {
    puVar2 = &DAT_803105a8;
  }
  if ((uVar3 & 0x40000000) != 0) {
    param_2 = (double)*(float *)(param_9 + 0x3a);
    if (param_2 < (double)FLOAT_803e0034) {
      if (((uVar3 & 0x1000000) == 0) || ((double)FLOAT_803e0034 <= param_2)) {
        param_2 = (double)FLOAT_803e003c;
        *(float *)(param_9 + 0x3a) =
             -(float)(param_2 * (double)FLOAT_803dc074 - (double)*(float *)(param_9 + 0x3a));
      }
      else {
        *(float *)(param_9 + 0x3a) =
             -(float)((double)FLOAT_803e0038 * (double)FLOAT_803dc074 - param_2);
      }
      goto LAB_8009ba84;
    }
  }
  if (((uVar3 & 0x1000000) == 0) ||
     (param_2 = (double)*(float *)(param_9 + 0x3a), param_2 <= (double)FLOAT_803e0040)) {
    if (((uVar3 & 8) != 0) &&
       (param_2 = (double)*(float *)(param_9 + 0x3a), (double)FLOAT_803e0040 < param_2)) {
      *(float *)(param_9 + 0x3a) =
           (float)((double)FLOAT_803e003c * (double)FLOAT_803dc074 + param_2);
    }
  }
  else {
    *(float *)(param_9 + 0x3a) = (float)((double)FLOAT_803e0038 * (double)FLOAT_803dc074 + param_2);
  }
LAB_8009ba84:
  dVar10 = (double)FLOAT_803e0044;
  *(float *)(param_9 + 0x2c) =
       (float)((double)*(float *)(param_9 + 0x38) * dVar10 + (double)*(float *)(param_9 + 0x2c));
  *(float *)(param_9 + 0x2e) =
       (float)((double)*(float *)(param_9 + 0x3a) * dVar10 + (double)*(float *)(param_9 + 0x2e));
  dVar9 = (double)*(float *)(param_9 + 0x3c);
  *(float *)(param_9 + 0x30) = (float)(dVar9 * dVar10 + (double)*(float *)(param_9 + 0x30));
  dVar1 = DOUBLE_803dfff8;
  if ((*(uint *)(param_9 + 0x3e) & 0x100000) == 0) {
    if ((*(uint *)(param_9 + 0x40) & 0x2000) != 0) {
      uVar3 = 0x43300000;
      local_8 = (double)CONCAT44(0x43300000,(uint)(ushort)param_9[0x44]);
      dVar9 = (double)(float)(local_8 - DOUBLE_803dfff8);
      param_9[0x42] =
           (short)(int)-(float)(dVar9 * dVar10 -
                               (double)(float)((double)CONCAT44(0x43300000,
                                                                (uint)(ushort)param_9[0x42]) -
                                              DOUBLE_803dfff8));
      param_2 = dVar1;
    }
  }
  else {
    uVar3 = 0x43300000;
    local_18 = (double)CONCAT44(0x43300000,(uint)(ushort)param_9[0x44]);
    dVar9 = (double)(float)(local_18 - DOUBLE_803dfff8);
    param_9[0x42] =
         (short)(int)(dVar9 * dVar10 +
                     (double)(float)((double)CONCAT44(0x43300000,(uint)(ushort)param_9[0x42]) -
                                    DOUBLE_803dfff8));
    param_2 = dVar1;
  }
  if (iVar5 != 0) {
    uVar6 = 0;
    uVar4 = 0;
    uVar8 = 0;
    uVar7 = 0;
    if (iVar5 != 0) {
      uVar8 = 0x80;
      uVar6 = 0x80;
      uVar7 = 0;
      if ((*(uint *)(param_9 + 0x3e) & 0x80) != 0) {
        uVar7 = 0x80;
        uVar8 = 0;
      }
      if ((*(uint *)(param_9 + 0x3e) & 0x40) != 0) {
        uVar4 = 0x80;
        uVar6 = 0;
      }
    }
    *param_9 = *puVar2;
    param_9[1] = puVar2[1];
    param_9[2] = puVar2[2];
    param_9[4] = uVar8;
    param_9[5] = uVar6;
    param_9[8] = puVar2[3];
    param_9[9] = puVar2[4];
    param_9[10] = puVar2[5];
    param_9[0xc] = uVar7;
    param_9[0xd] = uVar6;
    param_9[0x10] = puVar2[6];
    param_9[0x11] = puVar2[7];
    param_9[0x12] = puVar2[8];
    param_9[0x14] = uVar7;
    param_9[0x15] = uVar4;
    param_9[0x18] = puVar2[9];
    param_9[0x19] = puVar2[10];
    param_9[0x1a] = puVar2[0xb];
    param_9[0x1c] = uVar8;
    param_9[0x1d] = uVar4;
  }
  else {
    FUN_80137c30(dVar9,param_2,dVar10,param_4,param_5,param_6,param_7,param_8,s_notexture_803107dc,
                 &DAT_80310458,puVar2,uVar3,0,in_r8,in_r9,in_r10);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8009bc54
 * EN v1.0 Address: 0x8009BC54
 * EN v1.0 Size: 9252b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009bc54(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8009e078
 * EN v1.0 Address: 0x8009E078
 * EN v1.0 Size: 536b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8009e078(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,int param_10,int param_11,undefined4 param_12)
{
  short *psVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  
  iVar4 = 0;
  piVar3 = &DAT_8039c138;
  iVar5 = 0x50;
  piVar2 = piVar3;
  while ((((*(short *)(piVar2 + 3) == 0 || (piVar2[2] != param_9)) || (*piVar2 != param_10)) ||
         (piVar2[1] != param_11))) {
    piVar2 = piVar2 + 4;
    iVar4 = iVar4 + 1;
    iVar5 = iVar5 + -1;
    if (iVar5 == 0) {
      iVar5 = 0;
      iVar6 = 0x50;
      do {
        if (*(short *)(piVar3 + 3) == 0) {
          (&DAT_8039c144)[iVar5 * 8] = 1;
          (&DAT_8039c140)[iVar5 * 4] = param_9;
          (&DAT_8039c138)[iVar5 * 4] = param_10;
          (&DAT_8039c13c)[iVar5 * 4] = param_11;
          (&DAT_8039c146)[iVar5 * 8] = (short)param_12;
          return (int)(short)iVar5;
        }
        piVar3 = piVar3 + 4;
        iVar5 = iVar5 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
      FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   s_expgfx_c__exptab_is_FULL_80310810,param_10,param_11,param_12,piVar2,piVar3,
                   iVar4,iVar5);
      return -1;
    }
  }
  psVar1 = &DAT_8039c144 + iVar4 * 8;
  if (*psVar1 == -1) {
    FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 s_expgfx_c__addToTable_usage_overf_803107e8,psVar1,param_11,param_12,piVar2,
                 &DAT_8039c138,iVar4,in_r10);
    return -1;
  }
  *psVar1 = *psVar1 + 1;
  return (int)(short)iVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8009e290
 * EN v1.0 Address: 0x8009E290
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009e290(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  FUN_8009f164(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8009e2c0
 * EN v1.0 Address: 0x8009E2C0
 * EN v1.0 Size: 264b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009e2c0(void)
{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  byte *pbVar4;
  byte *pbVar5;
  int *piVar6;
  char *pcVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_80286830();
  iVar2 = 0;
  pcVar7 = &DAT_8039c828;
  piVar6 = &DAT_8039c688;
  pbVar5 = &DAT_8039c638;
  pbVar4 = &DAT_8039c7d8;
  pfVar3 = (float *)&DAT_8039b9b8;
  do {
    if ((((*pcVar7 != '\0') && (*piVar6 == (int)((ulonglong)uVar8 >> 0x20))) &&
        ((uint)*pbVar5 == (int)uVar8 + 1U)) &&
       (uVar1 = FUN_8005eaf8((double)(*pfVar3 - FLOAT_803dda58),(double)(pfVar3[1] - FLOAT_803dda58)
                             ,(double)pfVar3[2],(double)pfVar3[3],
                             (double)(pfVar3[4] - FLOAT_803dda5c),
                             (double)(pfVar3[5] - FLOAT_803dda5c),
                             (float *)(&DAT_80310458 + (uint)*pbVar4 * 0x18)), (uVar1 & 0xff) != 0))
    {
      FUN_8009e3c8();
    }
    pcVar7 = pcVar7 + 1;
    piVar6 = piVar6 + 1;
    pbVar5 = pbVar5 + 1;
    pbVar4 = pbVar4 + 1;
    pfVar3 = pfVar3 + 6;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x50);
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8009e3c8
 * EN v1.0 Address: 0x8009E3C8
 * EN v1.0 Size: 2984b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009e3c8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8009ef70
 * EN v1.0 Address: 0x8009EF70
 * EN v1.0 Size: 468b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009ef70(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8009f144
 * EN v1.0 Address: 0x8009F144
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009f144(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  FUN_8009f164(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8009f164
 * EN v1.0 Address: 0x8009F164
 * EN v1.0 Size: 260b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009f164(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8009f268
 * EN v1.0 Address: 0x8009F268
 * EN v1.0 Size: 464b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009f268(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8009f438
 * EN v1.0 Address: 0x8009F438
 * EN v1.0 Size: 288b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009f438(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,double param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  byte bVar2;
  double dVar3;
  double dVar4;
  
  iVar1 = FUN_80008b4c(-1);
  if ((short)iVar1 != 1) {
    dVar4 = (double)FLOAT_803dc074;
    FLOAT_803ddedc = (float)((double)FLOAT_803ddedc + dVar4);
    if (FLOAT_803e0098 <= FLOAT_803ddedc) {
      FLOAT_803ddedc = FLOAT_803dffdc;
    }
    FLOAT_803ddee0 = (float)((double)FLOAT_803ddee0 + dVar4);
    if (FLOAT_803e0004 <= FLOAT_803ddee0) {
      FLOAT_803ddee0 = FLOAT_803dffdc;
    }
    FLOAT_803ddee4 = (float)((double)FLOAT_803ddee4 + dVar4);
    dVar3 = (double)FLOAT_803ddee4;
    if ((double)FLOAT_803dffd4 <= dVar3) {
      FLOAT_803ddee4 = FLOAT_803dffdc;
    }
    DAT_803dd430 = 1;
    FUN_8009bc54(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8);
    DAT_803dd430 = 0;
    bVar2 = 0x50;
    while (bVar2 != 0) {
      bVar2 = bVar2 - 1;
      (&DAT_80310528)[bVar2] = 0;
    }
    (**(code **)(*DAT_803dd708 + 0xc))(0);
    DAT_803dded4 = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8009f558
 * EN v1.0 Address: 0x8009F558
 * EN v1.0 Size: 2576b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009f558(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,short param_11,undefined param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}
