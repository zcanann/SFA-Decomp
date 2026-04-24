// Function: FUN_801be44c
// Entry: 801be44c
// Size: 1056 bytes

void FUN_801be44c(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  short sVar2;
  int iVar3;
  short sVar5;
  undefined4 uVar4;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined uStack40;
  undefined local_27;
  undefined local_26;
  undefined local_25 [37];
  
  iVar3 = FUN_802860dc();
  iVar8 = *(int *)(iVar3 + 0xb8);
  iVar7 = *(int *)(iVar3 + 0x4c);
  if (DAT_803ddb90 != 0) {
    FUN_8001d9f4(DAT_803ddb90,local_25,&local_26,&local_27,&uStack40);
    FUN_8001d71c(DAT_803ddb90,local_25[0],local_26,local_27,0xc0);
    if ((*(char *)(DAT_803ddb90 + 0x2f8) != '\0') && (*(char *)(DAT_803ddb90 + 0x4c) != '\0')) {
      sVar2 = (ushort)*(byte *)(DAT_803ddb90 + 0x2f9) + (short)*(char *)(DAT_803ddb90 + 0x2fa);
      if (sVar2 < 0) {
        sVar2 = 0;
        *(undefined *)(DAT_803ddb90 + 0x2fa) = 0;
      }
      else if (0xc < sVar2) {
        sVar5 = FUN_800221a0(0xfffffff4,0xc);
        sVar2 = sVar2 + sVar5;
        if (0xff < sVar2) {
          sVar2 = 0xff;
          *(undefined *)(DAT_803ddb90 + 0x2fa) = 0;
        }
      }
      *(char *)(DAT_803ddb90 + 0x2f9) = (char)sVar2;
    }
  }
  if (*(int *)(iVar3 + 0xf4) == 0) {
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
      bVar1 = *(byte *)(param_3 + iVar6 + 0x81);
      if (bVar1 == 3) {
        (**(code **)(*DAT_803dcaac + 0x50))(0x1c,1,0);
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          FUN_80089710(7,1,0);
          FUN_800894a8((double)FLOAT_803e4cc4,(double)FLOAT_803e4cc4,(double)FLOAT_803e4cb8,7);
          FUN_800895e0(7,0xff,0xb4,0xb4,0x7f,0x28);
          FUN_80008cbc(iVar3,iVar3,0xd8,0);
          FUN_8000a518(0xee,1);
        }
        else if (bVar1 != 0) {
          (**(code **)(*DAT_803dcaac + 0x50))(0x1c,1,1);
        }
      }
      else if (bVar1 == 5) {
        if (DAT_803ddb90 != 0) {
          FUN_8001db6c((double)FLOAT_803e4cb8,DAT_803ddb90,0);
        }
      }
      else if ((bVar1 < 5) && (DAT_803ddb90 != 0)) {
        FUN_8001db6c((double)FLOAT_803e4cb8,DAT_803ddb90,1);
      }
    }
    if (FLOAT_803ddb9c <= FLOAT_803ddba0) {
      FUN_8000bb18(iVar3,0x189);
      FLOAT_803ddb9c = FLOAT_803ddb9c + FLOAT_803e4cbc;
      FUN_80014aa0((double)FLOAT_803e4cc0);
    }
    FLOAT_803ddba0 = FLOAT_803ddba0 + FLOAT_803db414;
    if (*(short *)(iVar3 + 0xb4) != -1) {
      iVar6 = (**(code **)(*DAT_803dcab8 + 0x30))(iVar3,iVar8,1);
      if (iVar6 == 0) {
        uVar4 = 1;
        goto LAB_801be854;
      }
      if ((*(short *)(iVar8 + 0x3f6) != -1) && (iVar6 = FUN_8001ffb4(), iVar6 != 0)) {
        (**(code **)(*DAT_803dca54 + 0x58))(param_3,(int)*(short *)(iVar7 + 0x2c));
        *(undefined2 *)(iVar8 + 0x3f6) = 0xffff;
      }
      bVar1 = *(byte *)(iVar8 + 0x405);
      if (bVar1 == 1) {
        iVar7 = (**(code **)(*DAT_803dcab8 + 0x34))
                          (iVar3,param_3,iVar8,&DAT_803ddbb0,&DAT_803ddba8,0);
        if (iVar7 != 0) {
          (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e4c90,iVar3,iVar8,1);
        }
      }
      else if ((bVar1 == 0) || (2 < bVar1)) {
        *(undefined2 *)(param_3 + 0x6e) = 0xffff;
        *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
      }
      else {
        *(undefined2 *)(param_3 + 0x6e) = 0;
        FUN_801be19c(iVar3,param_3,iVar8,iVar8);
        if (*(char *)(iVar8 + 0x405) == '\x01') {
          *(undefined2 *)(iVar8 + 0x270) = 0;
          (**(code **)(*DAT_803dca8c + 8))
                    ((double)FLOAT_803e4cb8,(double)FLOAT_803e4cb8,iVar3,iVar8,&DAT_803ddbb0,
                     &DAT_803ddba8);
          *(undefined *)(param_3 + 0x56) = 0;
        }
      }
    }
    if (*(short *)(iVar3 + 0xb4) == -1) {
      *(ushort *)(iVar8 + 0x400) = *(ushort *)(iVar8 + 0x400) | 2;
      uVar4 = 0;
    }
    else {
      uVar4 = 0;
    }
  }
  else {
    uVar4 = 0;
  }
LAB_801be854:
  FUN_80286128(uVar4);
  return;
}

