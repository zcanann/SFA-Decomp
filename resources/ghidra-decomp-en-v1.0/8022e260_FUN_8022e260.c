// Function: FUN_8022e260
// Entry: 8022e260
// Size: 432 bytes

void FUN_8022e260(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  
  local_28 = DAT_802c25e8;
  local_24 = DAT_802c25ec;
  local_20 = DAT_802c25f0;
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = iVar2 + 0xc0;
  *(code **)(param_1 + 0xbc) = FUN_8022c7b4;
  (**(code **)(*DAT_803dcaa8 + 4))(iVar1,4,0x1040006,1);
  (**(code **)(*DAT_803dcaa8 + 0xc))(iVar1,3,&DAT_8032b408,&DAT_8032b480,&local_28);
  (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar1);
  FUN_80037200(param_1,0x26);
  DAT_803ddd88 = param_1;
  FUN_80035960(param_1,1);
  *(undefined *)(iVar2 + 0x480) = 1;
  switch(*(undefined *)(param_1 + 0xac)) {
  case 0x26:
    break;
  default:
    *(undefined *)(iVar2 + 0x480) = 0;
    break;
  case 0x3a:
    *(undefined *)(iVar2 + 0x47b) = 0;
    *(undefined *)(iVar2 + 0x471) = 1;
    *(undefined *)(iVar2 + 0x47e) = 0;
    break;
  case 0x3b:
    *(undefined *)(iVar2 + 0x47b) = 1;
    *(undefined *)(iVar2 + 0x471) = 3;
    *(undefined *)(iVar2 + 0x47e) = 1;
    break;
  case 0x3c:
    *(undefined *)(iVar2 + 0x47b) = 3;
    *(undefined *)(iVar2 + 0x471) = 5;
    *(undefined *)(iVar2 + 0x47e) = 2;
    break;
  case 0x3d:
    *(undefined *)(iVar2 + 0x47b) = 2;
    *(undefined *)(iVar2 + 0x471) = 7;
    *(undefined *)(iVar2 + 0x47e) = 3;
    break;
  case 0x3e:
    *(undefined *)(iVar2 + 0x47b) = 4;
    *(undefined *)(iVar2 + 0x471) = 10;
    *(undefined *)(iVar2 + 0x47e) = 4;
  }
  return;
}

