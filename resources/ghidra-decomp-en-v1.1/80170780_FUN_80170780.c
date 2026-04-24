// Function: FUN_80170780
// Entry: 80170780
// Size: 172 bytes

/* WARNING: Removing unreachable block (ram,0x80170810) */
/* WARNING: Removing unreachable block (ram,0x80170790) */

int FUN_80170780(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
                undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)

{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar4;
  
  dVar4 = param_1;
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) == 0) {
    iVar2 = 0;
  }
  else {
    puVar3 = FUN_8002becc(0x24,0x836);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0x18);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x1c);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x20);
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    iVar2 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                         0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar2 != 0) {
      *(float *)(iVar2 + 8) = (float)dVar4;
    }
  }
  return iVar2;
}

