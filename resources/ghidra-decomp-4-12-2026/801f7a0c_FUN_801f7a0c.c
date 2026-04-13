// Function: FUN_801f7a0c
// Entry: 801f7a0c
// Size: 1408 bytes

/* WARNING: Removing unreachable block (ram,0x801f7f6c) */
/* WARNING: Removing unreachable block (ram,0x801f7a1c) */

void FUN_801f7a0c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  char cVar1;
  byte bVar2;
  ushort *puVar3;
  uint uVar4;
  int iVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int unaff_r27;
  short sVar6;
  short sVar7;
  int iVar8;
  double extraout_f1;
  double dVar9;
  undefined8 uVar10;
  double dVar11;
  
  puVar3 = (ushort *)FUN_80286840();
  iVar8 = *(int *)(puVar3 + 0x5c);
  sVar7 = 0;
  sVar6 = 1;
  dVar11 = (double)FLOAT_803e6bb8;
  if (puVar3[0x23] == 0x262) {
    dVar9 = extraout_f1;
    uVar4 = FUN_80020078(0x38f);
    if (uVar4 == 0) {
      iVar5 = FUN_800395a4((int)puVar3,1);
      if ((iVar5 != 0) &&
         (*(short *)(iVar5 + 10) = *(short *)(iVar5 + 10) + -0x10, *(short *)(iVar5 + 10) < -0x3e0))
      {
        *(undefined2 *)(iVar5 + 10) = 0;
      }
      uVar4 = FUN_80020078(0x21b);
      if (uVar4 != 0) {
        sVar7 = 100;
      }
      uVar4 = FUN_80020078(0x21c);
      if (uVar4 != 0) {
        sVar7 = 200;
      }
      uVar4 = FUN_80020078(0x21d);
      if (uVar4 != 0) {
        sVar7 = 400;
      }
      uVar4 = FUN_80020078(0x21f);
      if (uVar4 != 0) {
        sVar7 = 800;
      }
      uVar4 = FUN_80020078(0x221);
      if (uVar4 != 0) {
        sVar7 = 0x640;
      }
      uVar4 = FUN_80020078(0x222);
      if (uVar4 != 0) {
        sVar7 = 0x1900;
        sVar6 = 3;
        dVar11 = (double)FLOAT_803e6c10;
      }
      if (*(short *)(iVar8 + 2) < sVar7) {
        *(ushort *)(iVar8 + 2) = *(short *)(iVar8 + 2) + (ushort)DAT_803dc070 * sVar6;
        *(float *)(puVar3 + 4) =
             -(float)(dVar11 * (double)FLOAT_803dc074 - (double)*(float *)(puVar3 + 4));
        param_2 = (double)FLOAT_803e6c14;
        dVar9 = (double)(float)(dVar11 * (double)FLOAT_803dc074);
        *(float *)(puVar3 + 8) = (float)(param_2 * dVar9 + (double)*(float *)(puVar3 + 8));
      }
      else {
        uVar4 = FUN_80020078(0x222);
        if ((uVar4 != 0) && (uVar4 = FUN_80020078(0x38d), uVar4 == 0)) {
          FUN_800201ac(0x38d,1);
          dVar9 = (double)FUN_800201ac(0x370,0);
          *(undefined *)(iVar8 + 0xd) = 0;
        }
      }
      uVar4 = FUN_80020078(0x38d);
      if (((uVar4 == 0) && (0x960 < *(short *)(iVar8 + 2))) &&
         (uVar4 = FUN_80022264(0,100), uVar4 == 0)) {
        param_2 = (double)FLOAT_803e6c18;
        FUN_8000e69c((double)(float)(param_2 *
                                    (double)((float)((double)CONCAT44(0x43300000,
                                                                      (int)*(short *)(iVar8 + 2) -
                                                                      0x960U ^ 0x80000000) -
                                                    DOUBLE_803e6c08) / FLOAT_803e6c1c)));
        dVar9 = (double)FUN_800201ac(0x370,1);
      }
      *puVar3 = *puVar3 + *(short *)(iVar8 + 2);
      if (*(char *)(iVar8 + 0xd) == '\0') {
        FUN_8002cc9c(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar3);
      }
    }
    else {
      FUN_8002cc9c(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar3);
    }
    goto LAB_801f7f6c;
  }
  if (puVar3[0x23] == 0x2c2) {
    uVar4 = FUN_80020078(0x38f);
    if (uVar4 != 0) {
      if (*(byte *)(puVar3 + 0x1b) < 0xfa) {
        unaff_r27 = (int)(short)((ushort)*(byte *)(puVar3 + 0x1b) + (ushort)DAT_803dc070);
      }
      if (0xfa < unaff_r27) {
        unaff_r27 = 0xfa;
      }
      *(char *)(puVar3 + 0x1b) = (char)unaff_r27;
      iVar8 = FUN_800395a4((int)puVar3,0);
      if ((iVar8 != 0) &&
         (*(ushort *)(iVar8 + 8) = *(short *)(iVar8 + 8) + (ushort)DAT_803dc070 * -8,
         *(short *)(iVar8 + 8) < -0x3e0)) {
        *(undefined2 *)(iVar8 + 8) = 0;
      }
    }
    goto LAB_801f7f6c;
  }
  dVar11 = extraout_f1;
  uVar4 = FUN_80020078(0x38f);
  if (uVar4 == 0) {
    puVar3[2] = puVar3[2] + *(short *)(iVar8 + 4);
    *puVar3 = *puVar3 + *(short *)(iVar8 + 2);
    uVar4 = FUN_80020078(0x38d);
    if ((uVar4 != 0) && (*(char *)((int)puVar3 + 0xad) == '\0')) {
      if (DAT_803de92a == 0) {
        if ((600 < DAT_803de928) && (uVar4 = FUN_80022264(0,10), uVar4 == 0)) {
          dVar11 = (double)FUN_8000e69c((double)FLOAT_803e6c20);
        }
        if ((0 < DAT_803de928) &&
           (DAT_803de928 = DAT_803de928 - (ushort)DAT_803dc070, DAT_803de928 < 1)) {
          DAT_803de928 = 0;
          FUN_800201ac(0x38d,0);
          dVar11 = (double)FUN_800201ac(0x38f,1);
        }
      }
      if (DAT_803de930 == 0) {
        if ((0 < DAT_803de92e) &&
           (DAT_803de92e = DAT_803de92e - (ushort)DAT_803dc070, DAT_803de92e < 0)) {
          DAT_803de92e = 0;
        }
      }
      else {
        if ((0 < DAT_803de930) &&
           (DAT_803de930 = DAT_803de930 - (ushort)DAT_803dc070, DAT_803de930 < 1)) {
          DAT_803de930 = 0;
          uVar10 = FUN_80008cbc(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                puVar3,puVar3,0x30,0,in_r7,in_r8,in_r9,in_r10);
          FUN_80008cbc(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,puVar3,
                       0x34,0,in_r7,in_r8,in_r9,in_r10);
        }
        uVar4 = FUN_80022264(0,8);
        if (uVar4 == 0) {
          FUN_8000e69c((double)FLOAT_803e6c20);
        }
      }
    }
    goto LAB_801f7f6c;
  }
  cVar1 = *(char *)((int)puVar3 + 0xad);
  if (cVar1 == '\0') {
    bVar2 = *(byte *)(puVar3 + 0x1b);
    if (bVar2 == 0xff) goto LAB_801f7d28;
    if (bVar2 != 0xff) {
      unaff_r27 = (int)(short)((ushort)bVar2 + (ushort)DAT_803dc070);
    }
    if (0xff < unaff_r27) {
      unaff_r27 = 0xff;
    }
    *(char *)(puVar3 + 0x1b) = (char)unaff_r27;
  }
  else {
LAB_801f7d28:
    if (cVar1 == '\x01') {
      bVar2 = *(byte *)(puVar3 + 0x1b);
      if (bVar2 != 0x55) {
        if (bVar2 < 0x55) {
          unaff_r27 = (int)(short)((ushort)bVar2 + (ushort)DAT_803dc070);
        }
        if (0x55 < unaff_r27) {
          unaff_r27 = 0x55;
        }
        *(char *)(puVar3 + 0x1b) = (char)unaff_r27;
        goto LAB_801f7da4;
      }
    }
    if (cVar1 == '\x02') {
      bVar2 = *(byte *)(puVar3 + 0x1b);
      if (bVar2 != 0x19) {
        if (bVar2 < 0x19) {
          unaff_r27 = (int)(short)((ushort)bVar2 + (ushort)DAT_803dc070);
        }
        if (0x19 < unaff_r27) {
          unaff_r27 = 0x19;
        }
        *(char *)(puVar3 + 0x1b) = (char)unaff_r27;
      }
    }
  }
LAB_801f7da4:
  if (*(char *)((int)puVar3 + 0xad) == '\0') {
    uVar4 = FUN_80022264(0,0x96);
    if (uVar4 == 0) {
      FUN_80022264(0,0xffff);
      FUN_80022264(0,0xffff);
      FUN_80022264(0,0xffff);
      FUN_8000bb38((uint)puVar3,0x81);
    }
    FUN_801f74dc(puVar3);
  }
LAB_801f7f6c:
  FUN_8028688c();
  return;
}

