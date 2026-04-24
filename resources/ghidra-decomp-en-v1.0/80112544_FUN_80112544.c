// Function: FUN_80112544
// Entry: 80112544
// Size: 412 bytes

void FUN_80112544(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,short param_7,undefined4 param_8)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined8 uVar4;
  undefined4 local_30;
  int local_2c;
  int local_28 [10];
  
  uVar4 = FUN_802860d0();
  uVar2 = (undefined4)((ulonglong)uVar4 >> 0x20);
  iVar3 = (int)uVar4;
  local_30 = 0;
LAB_801126a8:
  do {
    while( true ) {
      while( true ) {
        iVar1 = FUN_800374ec(uVar2,&local_2c,local_28,&local_30);
        if (iVar1 == 0) {
          uVar2 = 0;
          goto LAB_801126c8;
        }
        if (local_2c != 0xb) break;
        *(char *)(iVar3 + 0x34e) = (char)local_30;
      }
      if (10 < local_2c) break;
      if (local_2c == 3) {
        if (*(short *)(iVar3 + 0x270) == param_7) {
          *(undefined *)(iVar3 + 0x349) = 0;
          *(undefined4 *)(iVar3 + 0x2d0) = 0;
          *(short *)(iVar3 + 0x270) = (short)param_6;
          uVar2 = 2;
LAB_801126c8:
          FUN_8028611c(uVar2);
          return;
        }
      }
      else if (local_2c < 3) {
        if (local_2c == 1) goto LAB_80112628;
      }
      else if (local_2c < 5) {
        FUN_800378c4(local_28[0],5,uVar2,0);
      }
    }
    if (local_2c != 0xe0000) {
      if ((local_2c < 0xe0000) && (local_2c == 0xa0001)) {
LAB_80112628:
        if (*(short *)(iVar3 + 0x270) != param_7) {
          FUN_80112d80(uVar2,iVar3,param_3,param_4,param_5,param_6,param_8,0,1);
          *(short *)(iVar3 + 0x270) = param_7;
          *(undefined *)(iVar3 + 0x349) = 0;
          *(int *)(iVar3 + 0x2d0) = local_28[0];
          uVar2 = 1;
          goto LAB_801126c8;
        }
      }
      goto LAB_801126a8;
    }
    if (local_28[0] == *(int *)(iVar3 + 0x2d0)) {
      *(short *)(iVar3 + 0x270) = (short)param_6;
      *(undefined4 *)(iVar3 + 0x2d0) = 0;
      *(undefined *)(iVar3 + 0x349) = 0;
    }
  } while( true );
}

