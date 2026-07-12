#ifndef MAIN_AUDIO_SND_SYNTH_LEGACY_H_
#define MAIN_AUDIO_SND_SYNTH_LEGACY_H_

/* ABI-compatible call views used by audio TUs built with the older compiler. */
unsigned int sndFXCheck(unsigned int id);
void sndSeqVolume(unsigned int volume, unsigned short time, unsigned int handle, unsigned int mode);
void sndSeqMute(unsigned int handle, unsigned int mute, unsigned int time);
void sndSeqContinue(unsigned int handle);

#endif /* MAIN_AUDIO_SND_SYNTH_LEGACY_H_ */
