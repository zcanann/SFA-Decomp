// Function: FUN_8019e2a4
// Entry: 8019e2a4
// Size: 212 bytes

void FUN_8019e2a4(short *param_1)

{
  char cVar1;
  int iVar2;
  undefined4 local_28;
  int local_24;
  undefined4 local_20 [5];
  
  cVar1 = *(char *)(*(int *)(param_1 + 0x26) + 0x19);
  if (cVar1 == '\x01') {
    local_20[0] = 0;
    while (iVar2 = FUN_800374ec(param_1,&local_24,&local_28,local_20), iVar2 != 0) {
      if (local_24 == 0x110004) {
        FUN_800378c4(local_28,0x110004,param_1,0);
      }
    }
    DAT_803ddb10 = param_1;
    *param_1 = *param_1 + (ushort)DAT_803db410 * 0xb6;
  }
  else if ((cVar1 < '\x01') && (-1 < cVar1)) {
    FUN_8019d9f0();
  }
  return;
}

