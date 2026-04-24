// Function: FUN_80217ca8
// Entry: 80217ca8
// Size: 1800 bytes

/* WARNING: Removing unreachable block (ram,0x80218390) */
/* WARNING: Removing unreachable block (ram,0x80217f98) */
/* WARNING: Removing unreachable block (ram,0x80217cb8) */

void FUN_80217ca8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short *psVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  short *psVar5;
  undefined2 *puVar6;
  char cVar7;
  int in_r6;
  float *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar8;
  undefined2 *puVar9;
  int iVar10;
  int *piVar11;
  double dVar12;
  double in_f31;
  double in_ps31_1;
  undefined4 local_88;
  float local_84;
  float local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined auStack_74 [12];
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined auStack_5c [12];
  int local_50;
  int local_4c;
  int local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined4 local_30;
  uint uStack_2c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  psVar1 = (short *)FUN_8028683c();
  piVar11 = *(int **)(psVar1 + 0x5c);
  iVar10 = *(int *)(psVar1 + 0x26);
  iVar2 = FUN_8002bac4();
  *(float *)(psVar1 + 8) = *(float *)(psVar1 + 8) - (float)piVar11[0x68];
  if ((*(byte *)(piVar11 + 0x6a) & 1) != 0) {
    local_84 = FLOAT_803e7590;
    iVar3 = FUN_80036f50(0x4a,psVar1,&local_84);
    piVar11[0x65] = iVar3;
    if (iVar3 != 0) {
      *(undefined *)((int)piVar11 + 0x1a7) = 1;
      FUN_80037e24((int)psVar1,piVar11[0x65],0);
      FUN_80220120(piVar11[0x65]);
    }
    *(byte *)(piVar11 + 0x6a) = *(byte *)(piVar11 + 0x6a) & 0xfe;
  }
  if (((*(byte *)(piVar11 + 0x6a) >> 3 & 1) == 0) &&
     (uVar4 = FUN_80020078((int)*(short *)(iVar10 + 0x1e)), uVar4 != 0)) {
    *(byte *)(piVar11 + 0x6a) = *(byte *)(piVar11 + 0x6a) & 0xf7 | 8;
    *(byte *)(piVar11 + 0x6a) = *(byte *)(piVar11 + 0x6a) & 0x7f | 0x80;
    psVar1[3] = psVar1[3] | 0x4000;
  }
  if (-1 < *(char *)(piVar11 + 0x6a)) {
    if (piVar11[100] != 0) {
      *(undefined4 *)(piVar11[100] + 0xc) = *(undefined4 *)(psVar1 + 6);
      *(float *)(piVar11[100] + 0x10) = *(float *)(psVar1 + 8) - FLOAT_803e7594;
      *(undefined4 *)(piVar11[100] + 0x14) = *(undefined4 *)(psVar1 + 10);
    }
    if ((*(byte *)(piVar11 + 0x6a) >> 1 & 1) == 0) {
      param_2 = (double)FLOAT_803e759c;
      FUN_800984fc((double)FLOAT_803e7598,param_2,psVar1,'\x01',
                   5 - *(byte *)((int)piVar11 + 0x1a6) & 0xff);
      if (piVar11[100] != 0) {
        FUN_8017082c();
      }
      piVar11[0x66] = piVar11[0x66] + 1;
      if (*(char *)((int)piVar11 + 0x1a6) == '\0') goto LAB_80218390;
    }
    else {
      uVar4 = FUN_80020078((int)*(short *)(iVar10 + 0x20));
      if ((uVar4 != 0) &&
         (*(byte *)(piVar11 + 0x6a) = *(byte *)(piVar11 + 0x6a) & 0xfd, piVar11[100] != 0)) {
        FUN_8017082c();
      }
    }
    iVar3 = FUN_802178d0(psVar1,piVar11 + 0x4a);
    if ((iVar3 != 0) &&
       (((int)*(short *)(piVar11 + 0x69) == 0xffffffff ||
        (uVar4 = FUN_80020078((int)*(short *)(piVar11 + 0x69)), uVar4 == 0)))) {
      iVar8 = 1;
      dVar12 = (double)FUN_80021754((float *)(iVar3 + 0x18),(float *)(psVar1 + 0xc));
      local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x1a) ^ 0x80000000);
      if ((double)(float)(local_40 - DOUBLE_803e7570) <= dVar12) {
        *psVar1 = *psVar1 + DAT_803dcf14;
        psVar5 = (short *)FUN_800396d0((int)psVar1,0xb);
        *psVar5 = *psVar5 >> 1;
      }
      else {
        in_r6 = 0x168;
        in_r7 = (float *)(piVar11 + 4);
        iVar8 = FUN_80217524(psVar1,iVar3,(int)(piVar11 + 0x4c),0x168,in_r7);
        if (iVar8 != 0) {
          FUN_8000bb38((uint)psVar1,0x1ad);
        }
      }
      if ((iVar8 != 0) ||
         (local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x1a) ^ 0x80000000),
         (double)(float)(local_40 - DOUBLE_803e7570) <= dVar12)) {
        if (piVar11[0x65] != 0) {
          FUN_80220104(piVar11[0x65]);
        }
      }
      else {
        if (iVar3 == iVar2) {
          FUN_80296e2c(iVar2);
        }
        if (*(char *)((int)piVar11 + 0x1a7) == '\x01') {
          piVar11[0x67] = 0x1b5;
          FUN_80220120(piVar11[0x65]);
        }
        else if (*(char *)((int)piVar11 + 0x1a7) == '\0') {
          piVar11[0x67] = 0x429;
          iVar2 = FUN_80080434((float *)(piVar11 + 0x4b));
          if (iVar2 != 0) {
            local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x1c) ^ 0x80000000);
            dVar12 = (double)((float)(local_40 - DOUBLE_803e7570) / FLOAT_803e75a0);
            uVar4 = FUN_80222268(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 iVar3,(float *)(piVar11 + 4),&local_80);
            if (uVar4 != 0) {
              iVar2 = *(int *)(psVar1 + 0x5c);
              uVar4 = FUN_8002e144();
              if ((uVar4 & 0xff) == 0) {
                iVar2 = 0;
              }
              else {
                puVar9 = FUN_8002becc(0x20,0x429);
                *puVar9 = 0x429;
                *(undefined *)(puVar9 + 1) = 8;
                *(undefined *)(puVar9 + 2) = 1;
                *(undefined *)(puVar9 + 3) = 0xff;
                *(undefined *)((int)puVar9 + 5) = 1;
                *(undefined *)((int)puVar9 + 7) = 0xff;
                *(undefined4 *)(puVar9 + 4) = *(undefined4 *)(iVar2 + 0x10);
                *(undefined4 *)(puVar9 + 6) = *(undefined4 *)(iVar2 + 0x14);
                *(undefined4 *)(puVar9 + 8) = *(undefined4 *)(iVar2 + 0x18);
                in_r6 = -1;
                in_r7 = (float *)0x0;
                iVar2 = FUN_8002e088(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar9,5,*(undefined *)(psVar1 + 0x56),0xffffffff,(uint *)0x0,
                                     in_r8,in_r9,in_r10);
              }
              if (iVar2 != 0) {
                local_50 = piVar11[4];
                local_4c = piVar11[5];
                local_48 = piVar11[6];
                local_68 = local_80;
                local_64 = local_7c;
                local_60 = local_78;
                local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x1c) ^ 0x80000000);
                in_r6 = **(int **)(iVar2 + 0x68);
                (**(code **)(in_r6 + 0x24))
                          ((double)((float)(local_40 - DOUBLE_803e7570) / FLOAT_803e75a0),iVar2,
                           auStack_5c,auStack_74);
                *piVar11 = iVar2;
                FUN_8003042c((double)FLOAT_803e75a4,param_2,param_3,param_4,param_5,param_6,param_7,
                             param_8,psVar1,1,0,in_r6,in_r7,in_r8,in_r9,in_r10);
                piVar11[0x49] = (int)FLOAT_803e75a8;
                FUN_8000bb38((uint)psVar1,0x1ab);
                FUN_8000bb38((uint)psVar1,0x1ac);
              }
            }
            FUN_80080404((float *)(piVar11 + 0x4b),(short)((int)*(char *)(iVar10 + 0x19) << 2));
          }
        }
      }
    }
    puVar9 = (undefined2 *)piVar11[0x65];
    if (puVar9 != (undefined2 *)0x0) {
      if ((puVar9[0x58] & 0x40) == 0) {
        puVar6 = (undefined2 *)FUN_800396d0((int)psVar1,0xb);
        local_40 = (double)CONCAT44(0x43300000,(int)*psVar1 ^ 0x80000000);
        iVar2 = (int)((float)(local_40 - DOUBLE_803e7570) + FLOAT_803de9e8);
        local_38 = (double)(longlong)iVar2;
        *puVar9 = (short)iVar2;
        puVar9[1] = *puVar6;
      }
      else {
        piVar11[0x65] = 0;
      }
    }
    if ((*(byte *)(piVar11 + 0x6a) >> 2 & 1) == 0) {
      local_88 = 1;
      in_r6 = 0;
      in_r7 = (float *)*DAT_803dd71c;
      cVar7 = (*(code *)in_r7[0x23])((double)FLOAT_803e75b4,piVar11 + 7,psVar1,&local_88);
      if (cVar7 == '\0') {
        *(byte *)(piVar11 + 0x6a) = *(byte *)(piVar11 + 0x6a) & 0xfb | 4;
        *(int *)(psVar1 + 6) = piVar11[0x21];
        *(int *)(psVar1 + 10) = piVar11[0x23];
        *(int *)(psVar1 + 8) = piVar11[0x22];
      }
    }
    else {
      FUN_802229a8((double)(FLOAT_803e75ac * FLOAT_803dcf10),(double)FLOAT_803e75b0,
                   (double)FLOAT_803e75a0,(int)psVar1,(float *)(piVar11 + 7),'\x01');
      param_3 = (double)(*(float *)(psVar1 + 0x16) * FLOAT_803dc074);
      FUN_8002ba34((double)(*(float *)(psVar1 + 0x12) * FLOAT_803dc074),
                   (double)(*(float *)(psVar1 + 0x14) * FLOAT_803dc074),param_3,(int)psVar1);
    }
    iVar2 = FUN_8002ba84();
    if (iVar2 != 0) {
      in_r6 = 2;
      in_r7 = (float *)**(undefined4 **)(iVar2 + 0x68);
      (*(code *)in_r7[10])(iVar2,psVar1,1);
    }
    dVar12 = (double)FLOAT_803dc074;
    iVar2 = FUN_8002fb40((double)(float)piVar11[0x49],dVar12);
    if ((psVar1[0x50] == 1) && (iVar2 != 0)) {
      FUN_8003042c((double)FLOAT_803e75a4,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar1,0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      piVar11[0x49] = (int)FLOAT_803e75b8;
    }
    local_38 = (double)CONCAT44(0x43300000,(uint)*(ushort *)((int)piVar11 + 0x1aa));
    iVar2 = (int)(FLOAT_803e75bc * FLOAT_803dc074 + (float)(local_38 - DOUBLE_803e75c8));
    local_40 = (double)(longlong)iVar2;
    *(short *)((int)piVar11 + 0x1aa) = (short)iVar2;
    uStack_2c = (uint)*(ushort *)((int)piVar11 + 0x1aa);
    local_30 = 0x43300000;
    dVar12 = (double)FUN_802945e0();
    piVar11[0x68] = (int)(float)((double)FLOAT_803e7584 * dVar12);
    *(float *)(psVar1 + 8) = *(float *)(psVar1 + 8) + (float)piVar11[0x68];
  }
LAB_80218390:
  FUN_80286888();
  return;
}

