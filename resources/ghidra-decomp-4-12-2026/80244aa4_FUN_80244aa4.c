// Function: FUN_80244aa4
// Entry: 80244aa4
// Size: 24 bytes

uint FUN_80244aa4(void)

{
  uint in_MSR;
  
  returnFromInterrupt(in_MSR,in_MSR & 0xffffffcf);
  return in_MSR & 0xffffffcf;
}

