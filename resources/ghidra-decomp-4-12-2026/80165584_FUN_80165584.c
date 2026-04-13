// Function: FUN_80165584
// Entry: 80165584
// Size: 176 bytes

undefined4 FUN_80165584(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    (**(code **)(*DAT_803dd738 + 0x4c))(param_1,(int)*(short *)(iVar1 + 0x3f0),0xffffffff,0);
    (**(code **)(*DAT_803dd70c + 0x58))(param_1,param_2,0x3c,10,0);
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f2),1);
    *(undefined *)(iVar1 + 0x405) = 0;
  }
  return 0;
}

