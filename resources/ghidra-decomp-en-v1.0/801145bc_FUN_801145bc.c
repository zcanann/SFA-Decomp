// Function: FUN_801145bc
// Entry: 801145bc
// Size: 512 bytes

/* WARNING: Removing unreachable block (ram,0x8011479c) */

void FUN_801145bc(void)

{
  short *psVar1;
  int iVar2;
  char cVar5;
  int iVar3;
  short sVar4;
  uint in_r6;
  undefined4 in_r7;
  uint *in_r8;
  undefined4 uVar6;
  undefined8 extraout_f1;
  undefined8 in_f31;
  undefined8 uVar7;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar7 = FUN_802860d4();
  psVar1 = (short *)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  cVar5 = '\0';
  local_48 = FLOAT_803e1c90;
  if ((*in_r8 & 0x10) == 0) {
    uVar7 = extraout_f1;
    if ((*in_r8 & 4) == 0) {
      cVar5 = '\0';
      iVar2 = FUN_80010320(iVar3);
      if ((iVar2 != 0) || (*(int *)(iVar3 + 0x10) != 0)) {
        cVar5 = (**(code **)(*DAT_803dca9c + 0x90))(iVar3);
      }
      *(undefined4 *)(psVar1 + 6) = *(undefined4 *)(iVar3 + 0x68);
      *(undefined4 *)(psVar1 + 8) = *(undefined4 *)(iVar3 + 0x6c);
      *(undefined4 *)(psVar1 + 10) = *(undefined4 *)(iVar3 + 0x70);
      if (cVar5 != '\0') {
        *in_r8 = *in_r8 | 0x10;
      }
    }
    else {
      iVar2 = FUN_80114408(psVar1,0);
      if (iVar2 != 0) {
        local_44 = 0x19;
        local_40 = 0x15;
        (**(code **)(*DAT_803dca9c + 0x8c))
                  ((double)FLOAT_803e1cb0,iVar3,psVar1,&local_44,in_r6 & 0xff);
        *in_r8 = *in_r8 | 8;
      }
    }
    FUN_8002f5d4(uVar7,psVar1,in_r7);
    if (((*in_r8 & 1) != 0) &&
       (iVar3 = FUN_800658a4((double)*(float *)(psVar1 + 6),(double)*(float *)(psVar1 + 8),
                             (double)*(float *)(psVar1 + 10),psVar1,&local_48,0), iVar3 == 0)) {
      *(float *)(psVar1 + 8) = *(float *)(psVar1 + 8) - local_48;
    }
    if ((*in_r8 & 2) != 0) {
      sVar4 = FUN_800217c0((double)(*(float *)(psVar1 + 6) - *(float *)(psVar1 + 0x40)),
                           (double)(*(float *)(psVar1 + 10) - *(float *)(psVar1 + 0x44)));
      *psVar1 = *psVar1 + (short)((int)(short)(sVar4 + -0x8000) - (int)*psVar1 >> 3);
    }
  }
  else {
    cVar5 = '\x01';
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  FUN_80286120(cVar5);
  return;
}

