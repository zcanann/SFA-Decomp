// Function: FUN_80125244
// Entry: 80125244
// Size: 480 bytes

void FUN_80125244(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int local_18 [3];
  
  iVar1 = FUN_8002b9ec();
  iVar2 = FUN_8002b9ac();
  FUN_8025d324(0,0,0x280,0x1e0);
  FUN_80121188(param_1,&DAT_803a9398);
  if (iVar2 == 0) {
    DAT_803dd738 = 0;
    DAT_803dd73c = 0;
  }
  else {
    DAT_803dd738 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x24))(iVar2);
    DAT_803dd73c = (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2);
  }
  FUN_8011fe0c();
  iVar3 = (**(code **)(*DAT_803dca50 + 0x10))();
  if ((((iVar3 != 0x44) && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) && (DAT_803dd780 == '\0'))
     && ((iVar2 != 0 && (iVar1 = FUN_8002073c(), iVar1 == 0)))) {
    (**(code **)(**(int **)(iVar2 + 0x68) + 0x48))(iVar2,local_18);
    if ((DAT_803dd834 != 0) && (DAT_803dd830 != local_18[0])) {
      FUN_80054308();
      DAT_803dd830 = -1;
      DAT_803dd834 = 0;
    }
    if (((DAT_803dd834 == 0) && (-1 < local_18[0])) &&
       (*(short *)(&DAT_8031b618 + local_18[0] * 2) != -1)) {
      DAT_803dd834 = FUN_80054d54();
    }
    DAT_803dd830 = (short)local_18[0];
    if (DAT_803dd834 != 0) {
      FUN_8007719c((double)FLOAT_803e2018,(double)FLOAT_803e2038,DAT_803a8a24,0xff,0x100);
      FUN_8007719c((double)FLOAT_803e2018,(double)FLOAT_803e203c,DAT_803dd834,0xff,0x80);
    }
  }
  return;
}

