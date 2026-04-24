// Function: FUN_8014c4dc
// Entry: 8014c4dc
// Size: 184 bytes

void FUN_8014c4dc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  char cVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  if (((piVar2[0xb7] & 0x2000U) == 0) ||
     (cVar1 = FUN_8014a5b0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           piVar2,(float *)(param_9 + 0x18),(float *)(*piVar2 + 0x68)),
     cVar1 == '\0')) {
    cVar1 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)FLOAT_803e3270,*piVar2,param_9,&DAT_803dc8c0,0xffffffff);
    if (cVar1 == '\0') {
      piVar2[0xb7] = piVar2[0xb7] | 0x2000;
    }
    else {
      piVar2[0xb7] = piVar2[0xb7] & 0xffffdfff;
    }
  }
  return;
}

