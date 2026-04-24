// Function: FUN_801ddc20
// Entry: 801ddc20
// Size: 468 bytes

undefined4 FUN_801ddc20(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int local_28;
  int local_24;
  int local_20;
  int local_1c [3];
  
  iVar5 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  iVar4 = 0;
  do {
    if ((int)(uint)*(byte *)(param_3 + 0x8b) <= iVar4) {
      return 0;
    }
    bVar1 = *(byte *)(param_3 + iVar4 + 0x81);
    if (bVar1 == 2) {
      iVar2 = FUN_8002e0fc(&local_20,local_1c);
      piVar3 = (int *)(iVar2 + local_20 * 4);
      for (; local_20 < local_1c[0]; local_20 = local_20 + 1) {
        if ((*piVar3 != param_1) && (*(short *)(*piVar3 + 0x46) == 0x282)) {
          iVar2 = *(int *)(iVar2 + local_20 * 4);
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2,2);
          break;
        }
        piVar3 = piVar3 + 1;
      }
      *(byte *)(iVar5 + 0x26) = *(byte *)(iVar5 + 0x26) | 0x10;
    }
    else if (bVar1 < 2) {
      if (bVar1 != 0) {
        *(byte *)(iVar5 + 0x26) = *(byte *)(iVar5 + 0x26) | 1;
        (**(code **)(*DAT_803dca54 + 0x50))(0x44,1,0,0);
      }
    }
    else if (bVar1 < 4) {
      iVar2 = FUN_8002e0fc(&local_28,&local_24);
      piVar3 = (int *)(iVar2 + local_28 * 4);
      for (; local_28 < local_24; local_28 = local_28 + 1) {
        if ((*piVar3 != param_1) && (*(short *)(*piVar3 + 0x46) == 0x282)) {
          iVar2 = *(int *)(iVar2 + local_28 * 4);
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2,1);
          break;
        }
        piVar3 = piVar3 + 1;
      }
    }
    iVar4 = iVar4 + 1;
  } while( true );
}

