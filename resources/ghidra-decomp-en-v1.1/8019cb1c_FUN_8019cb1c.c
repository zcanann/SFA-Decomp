// Function: FUN_8019cb1c
// Entry: 8019cb1c
// Size: 476 bytes

void FUN_8019cb1c(undefined2 *param_1,int param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined2 local_14;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  local_1c = DAT_802c2a40;
  local_18 = DAT_802c2a44;
  local_14 = DAT_802c2a48;
  local_28 = DAT_802c2a4c;
  local_24 = DAT_802c2a50;
  local_20 = DAT_802c2a54;
  if (puVar2 != (undefined4 *)0x0) {
    FUN_80037a5c((int)param_1,4);
    uVar1 = FUN_80020078(0x4b);
    *(char *)(puVar2 + 0x2a0) = (char)uVar1;
    *(undefined4 *)(param_1 + 0x7a) = 1;
    *(code **)(param_1 + 0x5e) = FUN_8019c91c;
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
    puVar2[0x2a5] = 0;
    puVar2[0x1ff] = FLOAT_803e4da8;
    puVar2[0x2a4] = 6;
    *(undefined *)((int)puVar2 + 0xa9b) = 0;
    *(byte *)((int)puVar2 + 0x611) = *(byte *)((int)puVar2 + 0x611) | 0x28;
    *(undefined *)(puVar2 + 0x2a6) = 1;
    *(undefined *)((int)puVar2 + 0xa99) = 0;
    *(undefined *)((int)puVar2 + 0xa9a) = 0;
    uVar1 = FUN_80020078(0x57);
    if (uVar1 == 0) {
      uVar1 = FUN_80020078(0x60);
      if ((uVar1 != 0) && (*(char *)(param_2 + 0x19) == '\0')) {
        *(undefined *)(puVar2 + 0x2a0) = 4;
        FUN_80114420(8,param_1);
      }
    }
    else {
      *(undefined *)(puVar2 + 0x2a0) = 4;
      if (*(char *)(param_2 + 0x19) == '\0') {
        param_1[3] = param_1[3] | 0x4000;
        FUN_8002cf80((int)param_1);
      }
    }
    FUN_80036018((int)param_1);
    FUN_80115200((int)param_1,puVar2,0xe000,0x2800,4);
    FUN_80115318((int)puVar2,300,100);
    FUN_80114238((int)puVar2,(wchar_t *)&local_28,(wchar_t *)&local_1c);
    FUN_80080304(-0x7fcdcb64,0xf);
    *(byte *)((int)puVar2 + 0x611) = *(byte *)((int)puVar2 + 0x611) | 2;
  }
  return;
}

