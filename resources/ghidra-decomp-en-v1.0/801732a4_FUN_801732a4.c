// Function: FUN_801732a4
// Entry: 801732a4
// Size: 2120 bytes

void FUN_801732a4(void)

{
  float fVar1;
  short sVar2;
  byte bVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  undefined2 uVar7;
  int iVar8;
  double dVar9;
  undefined local_28;
  char local_27 [3];
  int local_24 [9];
  
  psVar4 = (short *)FUN_802860dc();
  iVar5 = FUN_8002b9ec();
  iVar8 = *(int *)(psVar4 + 0x5c);
  while (iVar6 = FUN_800374ec(psVar4,local_24,0,0), iVar6 != 0) {
    if (local_24[0] == 0x7000b) {
      iVar6 = *(int *)(*(int *)(psVar4 + 0x28) + 0x18);
      (**(code **)(*DAT_803dca78 + 0x18))(psVar4);
      FUN_800999b4((double)FLOAT_803e34b0,psVar4,*(undefined *)(iVar8 + 0x27c),0x28);
      FUN_80035f00(psVar4);
      FUN_8000bb18(psVar4,*(undefined2 *)(iVar8 + 0x274));
      FUN_8000b824(psVar4,0x56);
      FUN_80296a24(iVar5,(int)*(char *)(iVar6 + 0xb));
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) & 0xfa;
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 8;
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x40;
      *(float *)(iVar8 + 0x26c) = FLOAT_803e34b4;
      FUN_8007d6dc(s_2_Magic_collected_80320cfa + 2);
      *(undefined *)(psVar4 + 0x1b) = 1;
    }
  }
  if ((*(byte *)(iVar8 + 0x27a) & 0x10) == 0) {
    if (((*(byte *)(iVar8 + 0x27a) & 0x40) == 0) &&
       (dVar9 = (double)FUN_8002166c(psVar4 + 0xc,iVar5 + 0x18), dVar9 < (double)FLOAT_803e34b8)) {
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x10;
      local_28 = 0;
      (**(code **)(*DAT_803dca88 + 8))
                (psVar4,*(undefined2 *)(iVar8 + 0x272),0,0x10002,0xffffffff,&local_28);
      local_28 = 1;
      (**(code **)(*DAT_803dca88 + 8))
                (psVar4,*(undefined2 *)(iVar8 + 0x272),0,0x10002,0xffffffff,&local_28);
      local_28 = 2;
      (**(code **)(*DAT_803dca88 + 8))
                (psVar4,*(undefined2 *)(iVar8 + 0x272),0,0x10002,0xffffffff,&local_28);
    }
  }
  else {
    dVar9 = (double)FUN_8002166c(psVar4 + 0xc,iVar5 + 0x18);
    if ((double)FLOAT_803e34b8 <= dVar9) {
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) & 0xef;
      (**(code **)(*DAT_803dca78 + 0x18))(psVar4);
    }
  }
  if ((psVar4[3] & 0x2000U) != 0) {
    if ((*(byte *)(iVar8 + 0x27a) & 2) != 0) {
      *psVar4 = *psVar4 + (ushort)DAT_803db410 * 0x100;
      sVar2 = *(short *)(iVar8 + 0x278) - (ushort)DAT_803db410;
      *(short *)(iVar8 + 0x278) = sVar2;
      if (sVar2 < 0) {
        FUN_8000bb18(psVar4,0x56);
        uVar7 = FUN_800221a0(0xf0,300);
        *(undefined2 *)(iVar8 + 0x278) = uVar7;
      }
    }
    if (*(int *)(psVar4 + 0x62) != 0) {
      iVar5 = *(int *)(psVar4 + 0x32);
      if (iVar5 != 0) {
        *(uint *)(iVar5 + 0x30) = *(uint *)(iVar5 + 0x30) | 0x1000;
      }
      (**(code **)(*DAT_803dcaa8 + 0x20))(psVar4,iVar8);
      goto LAB_80173ad4;
    }
    iVar6 = *(int *)(psVar4 + 0x32);
    if (iVar6 != 0) {
      *(uint *)(iVar6 + 0x30) = *(uint *)(iVar6 + 0x30) & 0xffffefff;
    }
    *(undefined *)(iVar8 + 0x25b) = 1;
    fVar1 = FLOAT_803e34bc;
    if ((*(byte *)(iVar8 + 0x27a) & 3) == 0) {
      *(float *)(psVar4 + 0x12) = *(float *)(psVar4 + 0x12) * FLOAT_803e34bc;
      *(float *)(psVar4 + 0x16) = *(float *)(psVar4 + 0x16) * fVar1;
      *(float *)(psVar4 + 0x14) = -(FLOAT_803e34c0 * FLOAT_803db414 - *(float *)(psVar4 + 0x14));
    }
    *(float *)(iVar8 + 0x26c) = *(float *)(iVar8 + 0x26c) - FLOAT_803db414;
    bVar3 = *(byte *)(iVar8 + 0x27a);
    if ((bVar3 & 1) == 0) {
      if ((bVar3 & 4) == 0) {
        if (*(float *)(iVar8 + 0x26c) <= FLOAT_803e34c4) {
          FUN_8002cbc4(psVar4);
        }
        goto LAB_80173ad4;
      }
      if (*(float *)(iVar8 + 0x26c) <= FLOAT_803e34c4) {
        *(byte *)(iVar8 + 0x27a) = bVar3 & 0xfb;
        *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 8;
        *(float *)(iVar8 + 0x26c) = FLOAT_803e34b4;
        (**(code **)(*DAT_803dca78 + 0x18))(psVar4);
        if (*(int *)(psVar4 + 0x18) == 0) {
          for (local_27[0] = '\x1e'; local_27[0] != '\0'; local_27[0] = local_27[0] + -1) {
            (**(code **)(*DAT_803dca88 + 8))
                      (psVar4,*(undefined2 *)(iVar8 + 0x270),0,1,0xffffffff,local_27);
          }
        }
        *(undefined *)(psVar4 + 0x1b) = 1;
        FUN_8000bb18(psVar4,0x57);
      }
      FUN_8002b95c((double)(*(float *)(psVar4 + 0x12) * FLOAT_803db414),
                   (double)(*(float *)(psVar4 + 0x14) * FLOAT_803db414),
                   (double)(*(float *)(psVar4 + 0x16) * FLOAT_803db414),psVar4);
    }
    else {
      if (*(float *)(iVar8 + 0x26c) <= FLOAT_803e34c4) {
        *(byte *)(iVar8 + 0x27a) = bVar3 & 0xfe;
        *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 4;
        *(float *)(iVar8 + 0x26c) = FLOAT_803e34c8;
        *(undefined *)(psVar4 + 0x1b) = 0xff;
      }
      if (*(int *)(psVar4 + 0x18) == 0) {
        (**(code **)(*DAT_803dca88 + 8))(psVar4,*(undefined2 *)(iVar8 + 0x270),0,1,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(psVar4,*(undefined2 *)(iVar8 + 0x270),0,1,0xffffffff,0);
      }
    }
    if ((*(byte *)(iVar8 + 0x27a) & 3) == 0) {
      (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,psVar4,iVar8);
      (**(code **)(*DAT_803dcaa8 + 0x14))(psVar4,iVar8);
      (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,psVar4,iVar8);
      if (*(char *)(iVar8 + 0x261) != '\0') {
        dVar9 = (double)FUN_802931a0((double)(-*(float *)(psVar4 + 0x16) *
                                              -*(float *)(psVar4 + 0x16) +
                                             -*(float *)(psVar4 + 0x12) * -*(float *)(psVar4 + 0x12)
                                             + -*(float *)(psVar4 + 0x14) *
                                               -*(float *)(psVar4 + 0x14)));
        if ((double)FLOAT_803e34cc < dVar9) {
          FUN_8000bb18(psVar4,0x16b);
        }
        if (*(float *)(iVar8 + 0x6c) < FLOAT_803e34d0) {
          *(float *)(psVar4 + 0x12) = -*(float *)(psVar4 + 0x12);
          *(float *)(psVar4 + 0x16) = -*(float *)(psVar4 + 0x16);
          fVar1 = FLOAT_803e34d8;
          *(float *)(psVar4 + 0x12) = *(float *)(psVar4 + 0x12) * FLOAT_803e34d8;
          *(float *)(psVar4 + 0x16) = *(float *)(psVar4 + 0x16) * fVar1;
        }
        else {
          *(float *)(psVar4 + 0x14) = -*(float *)(psVar4 + 0x14);
          *(float *)(psVar4 + 0x14) = *(float *)(psVar4 + 0x14) * FLOAT_803e34d4;
        }
        bVar3 = *(char *)(iVar8 + 0x27b) + 1;
        *(byte *)(iVar8 + 0x27b) = bVar3;
        if (5 < bVar3) {
          *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 2;
          fVar1 = FLOAT_803e34c4;
          *(float *)(psVar4 + 0x12) = FLOAT_803e34c4;
          *(float *)(psVar4 + 0x14) = fVar1;
          *(float *)(psVar4 + 0x16) = fVar1;
        }
      }
    }
  }
  if (((*(byte *)(iVar8 + 0x27a) & 0x20) == 0) && ((*(byte *)(iVar8 + 0x27a) & 0x40) == 0)) {
    fVar1 = *(float *)(psVar4 + 8) - *(float *)(iVar5 + 0x10);
    if (fVar1 < FLOAT_803e34c4) {
      fVar1 = -fVar1;
    }
    if (((fVar1 < FLOAT_803e34dc) &&
        (dVar9 = (double)FUN_8002166c(psVar4 + 0xc,iVar5 + 0x18),
        fVar1 = FLOAT_803e34e0 + *(float *)(iVar8 + 0x268), dVar9 < (double)(fVar1 * fVar1))) &&
       (iVar6 = FUN_8029622c(iVar5), iVar6 != 0)) {
      iVar6 = FUN_8001ffb4(0x90d);
      if (iVar6 == 0) {
        *(undefined2 *)(iVar8 + 0x280) = 0xffff;
        FUN_800378c4(iVar5,0x7000a,psVar4,iVar8 + 0x280);
        FUN_80035f00(psVar4);
        FUN_800200e8(0x90d,1);
        *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x20;
      }
      else {
        iVar6 = *(int *)(*(int *)(psVar4 + 0x28) + 0x18);
        (**(code **)(*DAT_803dca78 + 0x18))(psVar4);
        FUN_800999b4((double)FLOAT_803e34b0,psVar4,*(undefined *)(iVar8 + 0x27c),0x28);
        FUN_80035f00(psVar4);
        FUN_8000bb18(psVar4,*(undefined2 *)(iVar8 + 0x274));
        FUN_8000b824(psVar4,0x56);
        FUN_80296a24(iVar5,(int)*(char *)(iVar6 + 0xb));
        *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) & 0xfa;
        *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 8;
        *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x40;
        *(float *)(iVar8 + 0x26c) = FLOAT_803e34b4;
        FUN_8007d6dc(s_2_Magic_collected_80320cfa + 2);
        *(undefined *)(psVar4 + 0x1b) = 1;
      }
    }
  }
LAB_80173ad4:
  FUN_80286128();
  return;
}

