// Function: FUN_8020930c
// Entry: 8020930c
// Size: 1012 bytes

/* WARNING: Removing unreachable block (ram,0x802094d4) */
/* WARNING: Removing unreachable block (ram,0x802096a8) */
/* WARNING: Removing unreachable block (ram,0x80209388) */

undefined4 FUN_8020930c(int param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  byte bVar4;
  undefined4 uVar2;
  int iVar3;
  int iVar5;
  
  bVar4 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  FUN_8000da58(0,0x48b);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    cVar1 = *(char *)(param_3 + iVar5 + 0x81);
    if (cVar1 == '\x01') {
      FUN_80041e3c(0);
      if (bVar4 == 2) {
        FUN_80042f78(0xb);
        uVar2 = FUN_800481b0(0xb);
        FUN_80043560(uVar2,0);
      }
      else if (bVar4 < 2) {
        (**(code **)(*DAT_803dcaac + 0x50))(7,0,0);
        (**(code **)(*DAT_803dcaac + 0x50))(7,2,0);
        (**(code **)(*DAT_803dcaac + 0x50))(7,3,0);
        (**(code **)(*DAT_803dcaac + 0x50))(7,7,0);
        (**(code **)(*DAT_803dcaac + 0x50))(7,10,0);
        (**(code **)(*DAT_803dcaac + 0x50))(10,7,0);
        FUN_800200e8(0x1ed,1);
        FUN_80042f78(0x17);
        uVar2 = FUN_800481b0(0x17);
        FUN_80043560(uVar2,0);
      }
      else if (bVar4 < 4) {
        FUN_80042f78(7);
        uVar2 = FUN_800481b0(7);
        FUN_80043560(uVar2,0);
      }
    }
    else if (cVar1 == '\x02') {
      if (bVar4 == 2) {
        FUN_800200e8(0x405,0);
        iVar3 = FUN_8001ffb4(0xff);
        if (iVar3 == 0) {
          iVar3 = FUN_8001ffb4(0xbfd);
          if (iVar3 == 0) {
            iVar3 = FUN_8001ffb4(0xc6e);
            if (iVar3 != 0) {
              (**(code **)(*DAT_803dcaac + 0x44))(0xb,4);
              (**(code **)(*DAT_803dcaac + 0x50))(0xb,8,1);
              (**(code **)(*DAT_803dcaac + 0x50))(0xb,9,1);
              FUN_800552e8(0x22,0);
            }
          }
          else {
            (**(code **)(*DAT_803dcaac + 0x44))(0xb,2);
            (**(code **)(*DAT_803dcaac + 0x50))(0xb,5,1);
            (**(code **)(*DAT_803dcaac + 0x50))(0xb,6,1);
            FUN_800552e8(0x20,0);
          }
        }
        else {
          (**(code **)(*DAT_803dcaac + 0x44))(0xb,3);
          (**(code **)(*DAT_803dcaac + 0x50))(0xb,8,1);
          (**(code **)(*DAT_803dcaac + 0x50))(0xb,9,1);
          FUN_800552e8(0x22,0);
        }
      }
      else if (bVar4 < 2) {
        FUN_800552e8(2,0);
      }
      else if (bVar4 < 4) {
        FUN_800552e8(0xf,0);
      }
      FUN_80014948(1);
    }
    else if (cVar1 == '\x03') {
      if (bVar4 == 3) {
        uVar2 = FUN_800481b0(0xb);
        FUN_800437bc(uVar2,0x20000000);
      }
      else if (bVar4 < 3) {
        uVar2 = FUN_800481b0(7);
        FUN_800437bc(uVar2,0x20000000);
      }
    }
  }
  return 0;
}

