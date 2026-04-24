// Function: FUN_801eff7c
// Entry: 801eff7c
// Size: 576 bytes

undefined4 FUN_801eff7c(int param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  int iVar2;
  
  DAT_803dc0f0 = (uint)DAT_803db410;
  *(undefined2 *)(param_3 + 0x6e) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    switch(*(undefined *)(param_3 + iVar2 + 0x81)) {
    case 1:
      *(undefined4 *)(param_1 + 0xf4) = 10;
      break;
    case 2:
      FUN_800066e0(param_1,param_1,0x77,0,0,0);
      FUN_800066e0(param_1,param_1,0x78,0,0,0);
      FUN_800066e0(param_1,param_1,0x80,0,0,0);
      break;
    case 3:
      (**(code **)(*DAT_803dca94 + 0x14))(0,0x1e,0x50);
      break;
    case 4:
      *(undefined4 *)(param_1 + 0xf4) = 0xc;
      break;
    case 5:
      *(undefined4 *)(param_1 + 0xf4) = 0xd;
      break;
    case 6:
      (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x34),1,0);
      (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x34),2,0);
      (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x34),4,0);
      FUN_800200e8(0xd1,0);
      break;
    case 7:
      DAT_803ddc70 = 1;
      break;
    case 8:
      DAT_803ddc70 = 0;
      break;
    case 9:
      *(undefined4 *)(param_1 + 0xf4) = 0xb;
    }
  }
  iVar2 = FUN_8001ffb4(0x429);
  if ((iVar2 != 0) &&
     (cVar1 = (**(code **)(*DAT_803dcaac + 0x4c))(*(undefined *)(param_1 + 0x34),2), cVar1 != '\0'))
  {
    (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x34),1,0);
    (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x34),2,0);
  }
  return 0;
}

