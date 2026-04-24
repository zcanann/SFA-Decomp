// Function: FUN_801bb99c
// Entry: 801bb99c
// Size: 432 bytes

void FUN_801bb99c(int param_1,char param_2)

{
  int *piVar1;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar2;
  double dVar3;
  double dVar4;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  piVar2 = *(int **)(*(int *)(param_1 + 0xb8) + 0x40c);
  if (*piVar2 == 0) {
    piVar1 = FUN_8001f58c(0,'\x01');
    *piVar2 = (int)piVar1;
    if (*piVar2 != 0) {
      FUN_8001dbf0(*piVar2,2);
      dVar3 = (double)(float)piVar2[0x17];
      dVar4 = (double)(float)piVar2[0x18];
      FUN_8001de4c((double)(float)piVar2[0x16],dVar3,dVar4,(int *)*piVar2);
      if (param_2 == '\0') {
        FUN_8001dbb4(*piVar2,0xff,0,0,0xff);
        FUN_8001dadc(*piVar2,0xff,0,0,0xff);
        FUN_8001d7f4((double)FLOAT_803e58c4,dVar3,dVar4,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar2,0,0xff
                     ,0,0,0xc0,in_r9,in_r10);
      }
      else {
        FUN_8001dbb4(*piVar2,0,0xff,0,0xff);
        FUN_8001dadc(*piVar2,0,0xff,0,0xff);
        FUN_8001d7f4((double)FLOAT_803e58c0,dVar3,dVar4,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar2,0,0,
                     0xff,0,0xc0,in_r9,in_r10);
      }
      FUN_8001dcfc((double)FLOAT_803e58c4,(double)FLOAT_803e58c8,*piVar2);
      FUN_8001dc18(*piVar2,1);
      FUN_8001dc30((double)FLOAT_803e5870,*piVar2,'\x01');
      FUN_8001db7c(*piVar2,0x40,0,0,0x40);
      FUN_8001daa4(*piVar2,0x40,0,0,0x40);
      FUN_8001d6e4(*piVar2,2,0x28);
      FUN_8001de04(*piVar2,1);
      FUN_8001d7d8((double)FLOAT_803e5854,*piVar2);
    }
  }
  return;
}

