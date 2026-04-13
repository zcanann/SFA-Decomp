// Function: FUN_80230d88
// Entry: 80230d88
// Size: 488 bytes

void FUN_80230d88(undefined2 *param_1,int param_2)

{
  char cVar1;
  short sVar2;
  char *pcVar3;
  
  pcVar3 = *(char **)(param_1 + 0x5c);
  sVar2 = param_1[0x23];
  if (sVar2 == 0x60c) {
    *pcVar3 = '\0';
  }
  else if (sVar2 == 0x819) {
    *pcVar3 = '\0';
    pcVar3[0x14] = pcVar3[0x14] & 0xefU | 0x10;
  }
  else if (sVar2 == 0x60b) {
    *pcVar3 = '\x02';
  }
  else if (sVar2 == 0x7fc) {
    *pcVar3 = '\x03';
  }
  else if (sVar2 == 0x7fb) {
    *pcVar3 = '\x04';
  }
  else {
    *pcVar3 = '\x02';
  }
  pcVar3[1] = *(char *)(param_2 + 0x19);
  cVar1 = pcVar3[1];
  if (((cVar1 == '\x02') || (cVar1 == '\x03')) || (cVar1 == '\x05')) {
    pcVar3[0x14] = pcVar3[0x14] & 0x7f;
    FUN_8002b95c((int)param_1,1);
  }
  else {
    pcVar3[0x14] = pcVar3[0x14] & 0x7fU | 0x80;
    FUN_80035ff8((int)param_1);
  }
  *(undefined2 *)(pcVar3 + 2) = *(undefined2 *)(param_2 + 0x1a);
  *(float *)(pcVar3 + 4) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
              DOUBLE_803e7d68) / FLOAT_803e7d5c;
  *(undefined4 *)(pcVar3 + 8) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(pcVar3 + 0xc) = *(undefined4 *)(param_1 + 8);
  if (*(char *)(param_2 + 0x18) == '\0') {
    pcVar3[0x14] = pcVar3[0x14] & 0xdf;
  }
  else {
    pcVar3[0x14] = pcVar3[0x14] & 0xdfU | 0x20;
  }
  *param_1 = 0x8000;
  if ((*pcVar3 == '\x03') || (*pcVar3 == '\x04')) {
    pcVar3[0x14] = pcVar3[0x14] & 0xefU | 0x10;
    *(float *)(pcVar3 + 0x10) = FLOAT_803e7d70;
  }
  else {
    param_1[3] = param_1[3] | 0x4000;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  return;
}

