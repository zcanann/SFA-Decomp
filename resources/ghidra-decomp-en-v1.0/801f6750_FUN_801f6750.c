// Function: FUN_801f6750
// Entry: 801f6750
// Size: 752 bytes

void FUN_801f6750(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  
  iVar2 = FUN_802860dc();
  iVar6 = *(int *)(iVar2 + 0xb8);
  uVar3 = FUN_8002b9ec();
  *(undefined *)(param_3 + 0x56) = 0;
  *(code **)(param_3 + 0xe8) = FUN_801f654c;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    if (*(short *)(iVar6 + 8) == 0) {
      cVar4 = *(char *)(param_3 + iVar5 + 0x81);
      if (cVar4 != '\0') {
        *(char *)(iVar6 + 0xc) = cVar4;
        bVar1 = *(byte *)(param_3 + iVar5 + 0x81);
        if (bVar1 != 3) {
          if (bVar1 < 3) {
            if (bVar1 == 1) {
              FUN_800200e8(0x143,1);
            }
            else if (bVar1 != 0) {
              FUN_800200e8(0x143,0);
            }
          }
          else if (bVar1 == 5) {
            FUN_800200e8(0x21d,1);
          }
          else if (bVar1 < 5) {
            FUN_800200e8(0x21d,1);
            FUN_80296518(uVar3,8,0);
            FUN_800200e8(0x277,1);
          }
        }
      }
    }
    else {
      bVar1 = *(byte *)(param_3 + iVar5 + 0x81);
      if (bVar1 == 0xb) {
        cVar4 = FUN_80088e08(0);
        if (cVar4 != '\0') {
          FUN_80008b74(0,0,0x217,0);
          FUN_80008b74(iVar2,iVar2,0x216,0);
          FUN_80008b74(iVar2,iVar2,0x84,0);
          FUN_80008b74(iVar2,iVar2,0x8a,0);
          (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),4,0);
          (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),10,1);
          (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),0xb,1);
        }
      }
      else if (((bVar1 < 0xb) && (9 < bVar1)) && (cVar4 = FUN_80088e08(0), cVar4 == '\0')) {
        FUN_80008b74(0,0,0x22d,0);
        FUN_80008b74(iVar2,iVar2,0x22c,0);
        FUN_80008b74(iVar2,iVar2,0x229,0);
        FUN_80008b74(iVar2,iVar2,0x22a,0);
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),4,1);
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),10,0);
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),0xb,0);
      }
    }
    *(undefined *)(param_3 + iVar5 + 0x81) = 0;
  }
  FUN_80286128(0);
  return;
}

