// Function: FUN_80173750
// Entry: 80173750
// Size: 2120 bytes

void FUN_80173750(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  short sVar2;
  byte bVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 in_r7;
  char *in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar8;
  double dVar9;
  double dVar10;
  char local_28;
  char local_27 [3];
  uint local_24 [9];
  
  psVar4 = (short *)FUN_80286840();
  iVar5 = FUN_8002bac4();
  iVar8 = *(int *)(psVar4 + 0x5c);
  while (iVar6 = FUN_800375e4((int)psVar4,local_24,(uint *)0x0,(uint *)0x0), iVar6 != 0) {
    if (local_24[0] == 0x7000b) {
      iVar6 = *(int *)(*(int *)(psVar4 + 0x28) + 0x18);
      (**(code **)(*DAT_803dd6f8 + 0x18))(psVar4);
      FUN_80099c40((double)FLOAT_803e4148,psVar4,(uint)*(byte *)(iVar8 + 0x27c),0x28);
      FUN_80035ff8((int)psVar4);
      FUN_8000bb38((uint)psVar4,*(ushort *)(iVar8 + 0x274));
      FUN_8000b844((int)psVar4,0x56);
      FUN_80297184(iVar5,(int)*(char *)(iVar6 + 0xb));
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) & 0xfa;
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 8;
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x40;
      *(float *)(iVar8 + 0x26c) = FLOAT_803e414c;
      FUN_8007d858();
      *(undefined *)(psVar4 + 0x1b) = 1;
    }
  }
  if ((*(byte *)(iVar8 + 0x27a) & 0x10) == 0) {
    if (((*(byte *)(iVar8 + 0x27a) & 0x40) == 0) &&
       (dVar9 = FUN_80021730((float *)(psVar4 + 0xc),(float *)(iVar5 + 0x18)),
       dVar9 < (double)FLOAT_803e4150)) {
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x10;
      local_28 = '\0';
      (**(code **)(*DAT_803dd708 + 8))
                (psVar4,*(undefined2 *)(iVar8 + 0x272),0,0x10002,0xffffffff,&local_28);
      local_28 = '\x01';
      (**(code **)(*DAT_803dd708 + 8))
                (psVar4,*(undefined2 *)(iVar8 + 0x272),0,0x10002,0xffffffff,&local_28);
      local_28 = '\x02';
      in_r7 = 0xffffffff;
      in_r8 = &local_28;
      in_r9 = *DAT_803dd708;
      (**(code **)(in_r9 + 8))(psVar4,*(undefined2 *)(iVar8 + 0x272),0,0x10002);
    }
  }
  else {
    dVar9 = FUN_80021730((float *)(psVar4 + 0xc),(float *)(iVar5 + 0x18));
    if ((double)FLOAT_803e4150 <= dVar9) {
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) & 0xef;
      (**(code **)(*DAT_803dd6f8 + 0x18))(psVar4);
    }
  }
  if ((psVar4[3] & 0x2000U) != 0) {
    if ((*(byte *)(iVar8 + 0x27a) & 2) != 0) {
      *psVar4 = *psVar4 + (ushort)DAT_803dc070 * 0x100;
      sVar2 = *(short *)(iVar8 + 0x278) - (ushort)DAT_803dc070;
      *(short *)(iVar8 + 0x278) = sVar2;
      if (sVar2 < 0) {
        FUN_8000bb38((uint)psVar4,0x56);
        uVar7 = FUN_80022264(0xf0,300);
        *(short *)(iVar8 + 0x278) = (short)uVar7;
      }
    }
    if (*(int *)(psVar4 + 0x62) != 0) {
      iVar5 = *(int *)(psVar4 + 0x32);
      if (iVar5 != 0) {
        *(uint *)(iVar5 + 0x30) = *(uint *)(iVar5 + 0x30) | 0x1000;
      }
      (**(code **)(*DAT_803dd728 + 0x20))(psVar4,iVar8);
      goto LAB_80173f80;
    }
    iVar6 = *(int *)(psVar4 + 0x32);
    if (iVar6 != 0) {
      *(uint *)(iVar6 + 0x30) = *(uint *)(iVar6 + 0x30) & 0xffffefff;
    }
    *(undefined *)(iVar8 + 0x25b) = 1;
    fVar1 = FLOAT_803e4154;
    if ((*(byte *)(iVar8 + 0x27a) & 3) == 0) {
      *(float *)(psVar4 + 0x12) = *(float *)(psVar4 + 0x12) * FLOAT_803e4154;
      *(float *)(psVar4 + 0x16) = *(float *)(psVar4 + 0x16) * fVar1;
      param_2 = (double)FLOAT_803e4158;
      *(float *)(psVar4 + 0x14) =
           -(float)(param_2 * (double)FLOAT_803dc074 - (double)*(float *)(psVar4 + 0x14));
    }
    *(float *)(iVar8 + 0x26c) = *(float *)(iVar8 + 0x26c) - FLOAT_803dc074;
    bVar3 = *(byte *)(iVar8 + 0x27a);
    if ((bVar3 & 1) == 0) {
      if ((bVar3 & 4) == 0) {
        if ((double)*(float *)(iVar8 + 0x26c) <= (double)FLOAT_803e415c) {
          FUN_8002cc9c((double)*(float *)(iVar8 + 0x26c),param_2,param_3,param_4,param_5,param_6,
                       param_7,param_8,(int)psVar4);
        }
        goto LAB_80173f80;
      }
      if (*(float *)(iVar8 + 0x26c) <= FLOAT_803e415c) {
        *(byte *)(iVar8 + 0x27a) = bVar3 & 0xfb;
        *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 8;
        *(float *)(iVar8 + 0x26c) = FLOAT_803e414c;
        (**(code **)(*DAT_803dd6f8 + 0x18))(psVar4);
        if (*(int *)(psVar4 + 0x18) == 0) {
          for (local_27[0] = '\x1e'; local_27[0] != '\0'; local_27[0] = local_27[0] + -1) {
            in_r7 = 0xffffffff;
            in_r8 = local_27;
            in_r9 = *DAT_803dd708;
            (**(code **)(in_r9 + 8))(psVar4,*(undefined2 *)(iVar8 + 0x270),0,1);
          }
        }
        *(undefined *)(psVar4 + 0x1b) = 1;
        FUN_8000bb38((uint)psVar4,0x57);
      }
      param_3 = (double)(*(float *)(psVar4 + 0x16) * FLOAT_803dc074);
      FUN_8002ba34((double)(*(float *)(psVar4 + 0x12) * FLOAT_803dc074),
                   (double)(*(float *)(psVar4 + 0x14) * FLOAT_803dc074),param_3,(int)psVar4);
    }
    else {
      if (*(float *)(iVar8 + 0x26c) <= FLOAT_803e415c) {
        *(byte *)(iVar8 + 0x27a) = bVar3 & 0xfe;
        *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 4;
        *(float *)(iVar8 + 0x26c) = FLOAT_803e4160;
        *(undefined *)(psVar4 + 0x1b) = 0xff;
      }
      if (*(int *)(psVar4 + 0x18) == 0) {
        (**(code **)(*DAT_803dd708 + 8))(psVar4,*(undefined2 *)(iVar8 + 0x270),0,1,0xffffffff,0);
        in_r7 = 0xffffffff;
        in_r8 = (char *)0x0;
        in_r9 = *DAT_803dd708;
        (**(code **)(in_r9 + 8))(psVar4,*(undefined2 *)(iVar8 + 0x270),0,1);
      }
    }
    if ((*(byte *)(iVar8 + 0x27a) & 3) == 0) {
      (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,psVar4,iVar8);
      (**(code **)(*DAT_803dd728 + 0x14))(psVar4,iVar8);
      (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,psVar4,iVar8);
      if (*(char *)(iVar8 + 0x261) != '\0') {
        param_3 = -(double)*(float *)(psVar4 + 0x16);
        dVar9 = FUN_80293900((double)(float)(param_3 * param_3 +
                                            (double)(-*(float *)(psVar4 + 0x12) *
                                                     -*(float *)(psVar4 + 0x12) +
                                                    -*(float *)(psVar4 + 0x14) *
                                                    -*(float *)(psVar4 + 0x14))));
        if ((double)FLOAT_803e4164 < dVar9) {
          FUN_8000bb38((uint)psVar4,0x16b);
        }
        if (*(float *)(iVar8 + 0x6c) < FLOAT_803e4168) {
          *(float *)(psVar4 + 0x12) = -*(float *)(psVar4 + 0x12);
          *(float *)(psVar4 + 0x16) = -*(float *)(psVar4 + 0x16);
          fVar1 = FLOAT_803e4170;
          *(float *)(psVar4 + 0x12) = *(float *)(psVar4 + 0x12) * FLOAT_803e4170;
          *(float *)(psVar4 + 0x16) = *(float *)(psVar4 + 0x16) * fVar1;
        }
        else {
          *(float *)(psVar4 + 0x14) = -*(float *)(psVar4 + 0x14);
          *(float *)(psVar4 + 0x14) = *(float *)(psVar4 + 0x14) * FLOAT_803e416c;
        }
        bVar3 = *(char *)(iVar8 + 0x27b) + 1;
        *(byte *)(iVar8 + 0x27b) = bVar3;
        if (5 < bVar3) {
          *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 2;
          fVar1 = FLOAT_803e415c;
          *(float *)(psVar4 + 0x12) = FLOAT_803e415c;
          *(float *)(psVar4 + 0x14) = fVar1;
          *(float *)(psVar4 + 0x16) = fVar1;
        }
      }
    }
  }
  if (((*(byte *)(iVar8 + 0x27a) & 0x20) == 0) && ((*(byte *)(iVar8 + 0x27a) & 0x40) == 0)) {
    fVar1 = *(float *)(psVar4 + 8) - *(float *)(iVar5 + 0x10);
    if (fVar1 < FLOAT_803e415c) {
      fVar1 = -fVar1;
    }
    if (fVar1 < FLOAT_803e4174) {
      dVar9 = FUN_80021730((float *)(psVar4 + 0xc),(float *)(iVar5 + 0x18));
      dVar10 = (double)FLOAT_803e4178;
      fVar1 = (float)(dVar10 + (double)*(float *)(iVar8 + 0x268));
      if ((dVar9 < (double)(fVar1 * fVar1)) && (uVar7 = FUN_8029698c(iVar5), uVar7 != 0)) {
        uVar7 = FUN_80020078(0x90d);
        if (uVar7 == 0) {
          *(undefined2 *)(iVar8 + 0x280) = 0xffff;
          FUN_800379bc(dVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,0x7000a,
                       (uint)psVar4,iVar8 + 0x280,in_r7,in_r8,in_r9,in_r10);
          FUN_80035ff8((int)psVar4);
          FUN_800201ac(0x90d,1);
          *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x20;
        }
        else {
          iVar6 = *(int *)(*(int *)(psVar4 + 0x28) + 0x18);
          (**(code **)(*DAT_803dd6f8 + 0x18))(psVar4);
          FUN_80099c40((double)FLOAT_803e4148,psVar4,(uint)*(byte *)(iVar8 + 0x27c),0x28);
          FUN_80035ff8((int)psVar4);
          FUN_8000bb38((uint)psVar4,*(ushort *)(iVar8 + 0x274));
          FUN_8000b844((int)psVar4,0x56);
          FUN_80297184(iVar5,(int)*(char *)(iVar6 + 0xb));
          *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) & 0xfa;
          *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 8;
          *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x40;
          *(float *)(iVar8 + 0x26c) = FLOAT_803e414c;
          FUN_8007d858();
          *(undefined *)(psVar4 + 0x1b) = 1;
        }
      }
    }
  }
LAB_80173f80:
  FUN_8028688c();
  return;
}

