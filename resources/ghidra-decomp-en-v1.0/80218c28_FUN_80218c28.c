// Function: FUN_80218c28
// Entry: 80218c28
// Size: 616 bytes

void FUN_80218c28(int param_1)

{
  bool bVar1;
  short sVar2;
  short *psVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  short *psVar7;
  
  psVar7 = &DAT_8032a730;
  iVar5 = *(int *)(param_1 + 0xb8);
  if ((*(char *)(iVar5 + 1) == '\0') && (psVar3 = (short *)FUN_8002b9ec(), psVar3 != (short *)0x0))
  {
    uVar4 = FUN_800571e4();
    (**(code **)(*DAT_803dcaac + 0x1c))(psVar3 + 6,(int)*psVar3,0,uVar4);
    *(undefined *)(iVar5 + 1) = 1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  uVar6 = 0;
  psVar3 = psVar7;
  do {
    iVar5 = FUN_8001ffb4((int)*psVar3);
    if (iVar5 != 0) {
      sVar2 = (&DAT_8032a730)[uVar6];
      goto LAB_80218ce8;
    }
    psVar3 = psVar3 + 1;
    uVar6 = uVar6 + 1;
  } while (uVar6 < 9);
  sVar2 = 0;
LAB_80218ce8:
  if (sVar2 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    uVar6 = 0;
    do {
      iVar5 = (**(code **)(*DAT_803dca68 + 0x20))((int)*psVar7);
      if (iVar5 != 0) {
        if (DAT_803dc968 == '\0') {
          iVar5 = *(int *)(param_1 + 0xb8);
          *(undefined4 *)(iVar5 + 4) = (&DAT_8032a768)[uVar6];
          if (uVar6 == 3) {
            *(undefined4 *)(iVar5 + 4) = 0x524;
LAB_80218de8:
            FUN_800200e8((int)(short)(&DAT_8032a744)[uVar6],1);
            FUN_800e7ed8(uVar6 & 0xff);
          }
          else if (((int)uVar6 < 3) && (-1 < (int)uVar6)) goto LAB_80218de8;
          FUN_800200e8((int)(short)(&DAT_8032a758)[uVar6],1);
        }
        else {
          iVar5 = *(int *)(param_1 + 0xb8);
          if (((int)uVar6 < 3) && (-1 < (int)uVar6)) {
            FUN_800200e8((int)(short)(&DAT_8032a744)[uVar6],1);
            FUN_800e7ed8(uVar6 & 0xff);
          }
          *(undefined4 *)(iVar5 + 4) = (&DAT_8032a768)[uVar6];
          FUN_800200e8((int)(short)(&DAT_8032a758)[uVar6],1);
        }
        bVar1 = true;
        goto LAB_80218e34;
      }
      psVar7 = psVar7 + 1;
      uVar6 = uVar6 + 1;
    } while (uVar6 < 9);
    bVar1 = false;
LAB_80218e34:
    if (bVar1) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      FUN_80014b3c(0,0x100);
    }
  }
  FUN_80041018(param_1);
  return;
}

