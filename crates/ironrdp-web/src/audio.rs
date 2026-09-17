//! Server-audio bridge for the browser client. Only PCM playback is offered;
//! microphone capture is intentionally not implemented.

use std::borrow::Cow;

use futures_channel::mpsc;
use ironrdp::rdpsnd::client::RdpsndClientHandler;
use ironrdp::rdpsnd::pdu::{AudioFormat, AudioFormatFlags, PitchPdu, VolumePdu, WaveFormat};
use tracing::error;
use wasm_bindgen::prelude::*;

use crate::session::RdpInputEvent;

#[derive(Debug)]
pub(crate) enum AudioBackendMessage {
    Pcm {
        rate: u32,
        channels: u16,
        bits: u16,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
struct AudioProxy {
    tx: mpsc::UnboundedSender<RdpInputEvent>,
}

impl AudioProxy {
    fn send(&self, message: AudioBackendMessage) {
        if self.tx.unbounded_send(RdpInputEvent::Audio(message)).is_err() {
            error!("audio event loop closed");
        }
    }
}

#[derive(Debug)]
pub(crate) struct WasmAudioBackend {
    proxy: AudioProxy,
    formats: Vec<AudioFormat>,
}

impl WasmAudioBackend {
    pub(crate) fn new(tx: mpsc::UnboundedSender<RdpInputEvent>) -> Self {
        let formats = [(44_100_u32, 2_u16), (48_000, 2), (22_050, 2), (16_000, 1)]
            .into_iter()
            .map(|(rate, channels)| AudioFormat {
                format: WaveFormat::PCM,
                n_channels: channels,
                n_samples_per_sec: rate,
                n_avg_bytes_per_sec: rate * u32::from(channels) * 2,
                n_block_align: channels * 2,
                bits_per_sample: 16,
                data: None,
            })
            .collect();
        Self {
            proxy: AudioProxy { tx },
            formats,
        }
    }
}

impl RdpsndClientHandler for WasmAudioBackend {
    fn get_flags(&self) -> AudioFormatFlags {
        AudioFormatFlags::VOLUME
    }

    fn get_formats(&self) -> &[AudioFormat] {
        &self.formats
    }

    fn wave(&mut self, format: &AudioFormat, _ts: u32, data: Cow<'_, [u8]>) {
        if format.format == WaveFormat::PCM && (format.bits_per_sample == 8 || format.bits_per_sample == 16) {
            self.proxy.send(AudioBackendMessage::Pcm {
                rate: format.n_samples_per_sec,
                channels: format.n_channels,
                bits: format.bits_per_sample,
                data: data.into_owned(),
            });
        }
    }

    fn set_volume(&mut self, _: VolumePdu) {}
    fn set_pitch(&mut self, _: PitchPdu) {}
    fn close(&mut self) {}
}

#[derive(Debug, Clone)]
pub(crate) struct JsAudioCallbacks {
    pub(crate) on_pcm: js_sys::Function,
}

#[derive(Debug)]
pub(crate) struct WasmAudio {
    callbacks: JsAudioCallbacks,
}

impl WasmAudio {
    pub(crate) fn process_message(&self, message: AudioBackendMessage) {
        let AudioBackendMessage::Pcm {
            rate,
            channels,
            bits,
            data,
        } = message;
        let bytes = js_sys::Uint8Array::from(data.as_slice());
        if self
            .callbacks
            .on_pcm
            .call4(
                &JsValue::NULL,
                &bytes,
                &JsValue::from_f64(f64::from(rate)),
                &JsValue::from_f64(f64::from(channels)),
                &JsValue::from_f64(f64::from(bits)),
            )
            .is_err()
        {
            error!("browser audio callback failed");
        }
    }
}

pub(crate) fn wasm_audio_pair(
    tx: mpsc::UnboundedSender<RdpInputEvent>,
    callbacks: JsAudioCallbacks,
) -> (WasmAudioBackend, WasmAudio) {
    (WasmAudioBackend::new(tx), WasmAudio { callbacks })
}

#[cfg(test)]
mod tests {
    use ironrdp::rdpsnd::client::RdpsndClientHandler as _;

    use super::*;

    #[test]
    fn only_advertises_pcm_playback_formats() {
        let (tx, _) = mpsc::unbounded();
        let backend = WasmAudioBackend::new(tx);
        assert!(!backend.get_formats().is_empty());
        assert!(backend.get_formats().iter().all(|format| format.format == WaveFormat::PCM));
        assert!(backend.get_formats().iter().all(|format| format.bits_per_sample == 16));
    }
}
