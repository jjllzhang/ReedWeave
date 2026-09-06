//! Protocol-only Postcard codecs. See `docs/wire-format.md` for ordering and bounds.
use std::{fmt, marker::PhantomData};

use brakefri_primitives::{
    fields::CanonicalField,
    hash::{Digest, HashSuite},
    mmcs::{MatrixOpening, MultiProof},
    transcript::FieldProfile,
};
use brakefri_runtime::ExecutionContext;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, DeserializeSeed, Error as _, SeqAccess, Visitor},
    ser::{SerializeSeq, SerializeTuple},
};
use thiserror::Error;

use crate::{
    BrakeFri, BrakeParams, BrakeProof, Commitment, M, PcsError, Round, ScalarOpening,
    pcs::{boundary_bound, opening_bounds, validate_proof_shape},
};

#[derive(Debug, Error)]
pub enum EncodeError {
    #[error(transparent)]
    Shape(#[from] PcsError),
    #[error("proof serialization failed: {0}")]
    Postcard(#[from] postcard::Error),
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("commitment must contain exactly 32 bytes")]
    CommitmentLength,
    #[error(transparent)]
    Shape(#[from] PcsError),
    #[error("malformed, noncanonical, truncated, or oversized proof: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("trailing proof bytes")]
    TrailingBytes,
    #[error("noncanonical Postcard framing")]
    NonCanonicalFraming,
    #[error(transparent)]
    Encode(#[from] EncodeError),
}

pub fn encode_commitment(commitment: &Commitment) -> [u8; 32] {
    commitment.root
}

pub fn decode_commitment(bytes: &[u8]) -> Result<Commitment, DecodeError> {
    Ok(Commitment {
        root: bytes
            .try_into()
            .map_err(|_| DecodeError::CommitmentLength)?,
    })
}

/// Encode the same typed proof accepted by `BrakeFri::verify`; no statement or context.
/// Shape validation here does not establish cryptographic validity.
pub fn encode_eval_proof<P: FieldProfile>(
    params: &BrakeParams,
    proof: &BrakeProof<P>,
) -> Result<Vec<u8>, EncodeError> {
    validate_proof_shape(params, proof)?;
    let wire = WireProof {
        block_values: Fields(&proof.block_values),
        rounds: proof.rounds.iter().map(WireRound::from).collect(),
        terminal_constant: Coordinate(proof.terminal_constant),
        terminal_values: proof.terminal_values.map(Coordinate),
        initial_opening: WireInitial {
            rows: Rows(&proof.initial_opening.rows),
            boundary_digests: &proof.initial_opening.proof.sibling_hashes,
        },
        scalar_openings: proof
            .scalar_openings
            .iter()
            .map(|opening| WireScalar {
                values: Fields(&opening.values),
                boundary_digests: &opening.proof.sibling_hashes,
            })
            .collect(),
    };
    Ok(postcard::to_allocvec(&wire)?)
}

/// Every vector is parsed by a parameter-aware seed, checking its announced count
/// before reserving memory or visiting elements. Exact transcript-derived counts and
/// frontier consumption are still checked by typed verification.
pub fn decode_eval_proof<P: FieldProfile>(
    params: &BrakeParams,
    bytes: &[u8],
) -> Result<BrakeProof<P>, DecodeError> {
    if params.profile() != P::PROFILE {
        return Err(PcsError::ProfileMismatch.into());
    }
    let mut deserializer = postcard::Deserializer::from_bytes(bytes);
    let proof = ProofSeed::<P>(params, PhantomData).deserialize(&mut deserializer)?;
    if !deserializer.finalize()?.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    // Postcard accepts some overlong integer length representations. Require the
    // unique encoding as well as canonical coordinates. This pass is bounded and
    // belongs to decode/verify time, not an untimed preprocessing step.
    if encode_eval_proof(params, &proof)? != bytes {
        return Err(DecodeError::NonCanonicalFraming);
    }
    Ok(proof)
}

#[derive(Debug, Error)]
pub enum VerifyEncodedError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("received commitment differs from the application's expected commitment")]
    CommitmentMismatch,
    #[error(transparent)]
    Verify(#[from] PcsError),
    #[error("total protocol byte length overflow")]
    SizeOverflow,
}

impl<P: FieldProfile, S: HashSuite> BrakeFri<P, S> {
    /// Decode and verify the two actual transport buffers, returning their checked
    /// total byte length only after success. Call inside the verification timer.
    /// The expected root and intended (z, y) must come from the caller's statement.
    pub fn verify_encoded(
        &self,
        expected: &Commitment,
        statement: (P::Base, P::Base),
        commit_bytes: &[u8],
        eval_bytes: &[u8],
        execution: &ExecutionContext,
    ) -> Result<usize, VerifyEncodedError> {
        let received = decode_commitment(commit_bytes)?;
        if &received != expected {
            return Err(VerifyEncodedError::CommitmentMismatch);
        }
        let proof = decode_eval_proof(self.params(), eval_bytes)?;
        self.verify(&received, statement.0, statement.1, &proof, execution)?;
        commit_bytes
            .len()
            .checked_add(eval_bytes.len())
            .ok_or(VerifyEncodedError::SizeOverflow)
    }
}

// Fixed coordinate tuples: base fields have one coordinate; the quadratic has
// (constant, u). Arrays and tuples have no length prefix in Postcard. Never use
// the upstream field's integer Serde implementation here.
struct Coordinate<F>(F);
impl<F: CanonicalField> Serialize for Coordinate<F> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.0.to_canonical_bytes();
        let mut tuple = serializer.serialize_tuple(F::COORDINATE_COUNT)?;
        for coordinate in bytes.as_ref().chunks_exact(F::COORDINATE_BYTES) {
            match F::COORDINATE_BYTES {
                8 => tuple.serialize_element(
                    &<[u8; 8]>::try_from(coordinate).map_err(serde::ser::Error::custom)?,
                )?,
                16 => tuple.serialize_element(
                    &<[u8; 16]>::try_from(coordinate).map_err(serde::ser::Error::custom)?,
                )?,
                _ => return Err(serde::ser::Error::custom("unsupported coordinate width")),
            }
        }
        tuple.end()
    }
}
impl<'de, F: CanonicalField> Deserialize<'de> for Coordinate<F> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Coordinates<F>(PhantomData<F>);
        impl<'de, F: CanonicalField> Visitor<'de> for Coordinates<F> {
            type Value = Coordinate<F>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("fixed canonical coordinates")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut bytes = [0u8; 16];
                if F::BYTE_WIDTH > bytes.len() {
                    return Err(A::Error::custom("unsupported field width"));
                }
                for chunk in bytes[..F::BYTE_WIDTH].chunks_exact_mut(F::COORDINATE_BYTES) {
                    match F::COORDINATE_BYTES {
                        8 => chunk.copy_from_slice(&next::<_, [u8; 8]>(&mut seq)?),
                        16 => chunk.copy_from_slice(&next::<_, [u8; 16]>(&mut seq)?),
                        _ => return Err(A::Error::custom("unsupported coordinate width")),
                    }
                }
                F::from_canonical_bytes(&bytes[..F::BYTE_WIDTH])
                    .map(Coordinate)
                    .map_err(A::Error::custom)
            }
        }
        deserializer.deserialize_tuple(F::COORDINATE_COUNT, Coordinates(PhantomData))
    }
}

struct Fields<'a, F>(&'a [F]);
impl<F: CanonicalField> Serialize for Fields<'_, F> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for &value in self.0 {
            seq.serialize_element(&Coordinate(value))?;
        }
        seq.end()
    }
}
struct Rows<'a, F>(&'a [Vec<F>]);
impl<F: CanonicalField> Serialize for Rows<'_, F> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for row in self.0 {
            seq.serialize_element(&Fields(row))?;
        }
        seq.end()
    }
}

#[derive(Serialize)]
#[serde(bound(serialize = "F: CanonicalField, K: CanonicalField"))]
struct WireProof<'a, F, K> {
    block_values: Fields<'a, F>,
    rounds: Vec<WireRound<K>>,
    terminal_constant: Coordinate<K>,
    terminal_values: [Coordinate<K>; 2],
    initial_opening: WireInitial<'a, F>,
    scalar_openings: Vec<WireScalar<'a, K>>,
}
#[derive(Serialize, Deserialize)]
#[serde(bound = "K: CanonicalField")]
struct WireRound<K> {
    even_value: Coordinate<K>,
    odd_value: Coordinate<K>,
    next_oracle_root: Digest,
}
impl<K: Copy> From<&Round<K>> for WireRound<K> {
    fn from(round: &Round<K>) -> Self {
        Self {
            even_value: Coordinate(round.even_value),
            odd_value: Coordinate(round.odd_value),
            next_oracle_root: round.next_oracle_root,
        }
    }
}
#[derive(Serialize)]
#[serde(bound(serialize = "F: CanonicalField"))]
struct WireInitial<'a, F> {
    rows: Rows<'a, F>,
    boundary_digests: &'a [Digest],
}
#[derive(Serialize)]
#[serde(bound(serialize = "K: CanonicalField"))]
struct WireScalar<'a, K> {
    values: Fields<'a, K>,
    boundary_digests: &'a [Digest],
}

fn next<'de, A: SeqAccess<'de>, T: Deserialize<'de>>(seq: &mut A) -> Result<T, A::Error> {
    seq.next_element()?
        .ok_or_else(|| A::Error::custom("missing tuple element"))
}
fn seeded<'de, A: SeqAccess<'de>, S: DeserializeSeed<'de>>(
    seq: &mut A,
    seed: S,
) -> Result<S::Value, A::Error> {
    seq.next_element_seed(seed)?
        .ok_or_else(|| A::Error::custom("missing tuple element"))
}
struct ValueSeed<T>(PhantomData<T>);
impl<'de, T: DeserializeOwned> DeserializeSeed<'de> for ValueSeed<T> {
    type Value = T;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<T, D::Error> {
        T::deserialize(d)
    }
}
struct FieldSeed<F>(PhantomData<F>);
impl<'de, F: CanonicalField> DeserializeSeed<'de> for FieldSeed<F> {
    type Value = F;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<F, D::Error> {
        Ok(Coordinate::<F>::deserialize(d)?.0)
    }
}

/// All untrusted vectors go through this visitor. The factory receives the local
/// element index, so scalar layer bounds follow public geometry, not wire data.
struct Sequence<F> {
    min: usize,
    max: usize,
    element: F,
}
impl<'de, F, S> DeserializeSeed<'de> for Sequence<F>
where
    F: FnMut(usize) -> S,
    S: DeserializeSeed<'de>,
{
    type Value = Vec<S::Value>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_seq(self)
    }
}
impl<'de, F, S> Visitor<'de> for Sequence<F>
where
    F: FnMut(usize) -> S,
    S: DeserializeSeed<'de>,
{
    type Value = Vec<S::Value>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded protocol vector")
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Self::Value, A::Error> {
        // Postcard provides the wire length here, before any element is visited,
        // or None when even one byte per element would exceed the remaining input.
        let count = seq
            .size_hint()
            .ok_or_else(|| A::Error::custom("missing vector length"))?;
        if count < self.min || count > self.max {
            return Err(A::Error::custom("vector length outside public bounds"));
        }
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(A::Error::custom)?;
        for index in 0..count {
            values.push(seeded(&mut seq, (self.element)(index))?);
        }
        Ok(values)
    }
}
fn fields<F: CanonicalField>(
    min: usize,
    max: usize,
) -> Sequence<impl FnMut(usize) -> FieldSeed<F>> {
    Sequence {
        min,
        max,
        element: |_| FieldSeed(PhantomData),
    }
}

// An opening is exactly a values vector followed by a frontier digest vector.
// Once values are bounded, its actual count gives a tighter boundary limit.
struct OpeningSeed<S> {
    values: S,
    depth: usize,
}
impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for OpeningSeed<S>
where
    S::Value: OpeningValues,
{
    type Value = (S::Value, MultiProof);
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_tuple(2, self)
    }
}
trait OpeningValues {
    fn count(&self) -> usize;
}
impl<T> OpeningValues for Vec<T> {
    fn count(&self) -> usize {
        self.len()
    }
}
impl<'de, S: DeserializeSeed<'de>> Visitor<'de> for OpeningSeed<S>
where
    S::Value: OpeningValues,
{
    type Value = (S::Value, MultiProof);
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("values and frontier digests")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let values = seeded(&mut seq, self.values)?;
        let max = boundary_bound(values.count(), self.depth).map_err(A::Error::custom)?;
        let sibling_hashes = seeded(
            &mut seq,
            Sequence {
                min: 0,
                max,
                element: |_| ValueSeed::<Digest>(PhantomData),
            },
        )?;
        Ok((values, MultiProof { sibling_hashes }))
    }
}

struct ProofSeed<'a, P>(&'a BrakeParams, PhantomData<P>);
impl<'de, P: FieldProfile> DeserializeSeed<'de> for ProofSeed<'_, P> {
    type Value = BrakeProof<P>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_tuple(6, self)
    }
}
impl<'de, P: FieldProfile> Visitor<'de> for ProofSeed<'_, P> {
    type Value = BrakeProof<P>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("BrakeFRI evaluation proof")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let params = self.0;
        let block_values = seeded(&mut seq, fields::<P::Base>(M, M))?;
        let rounds = seeded(
            &mut seq,
            Sequence {
                min: params.rounds(),
                max: params.rounds(),
                element: |_| ValueSeed::<WireRound<P::Challenge>>(PhantomData),
            },
        )?
        .into_iter()
        .map(|round| Round {
            even_value: round.even_value.0,
            odd_value: round.odd_value.0,
            next_oracle_root: round.next_oracle_root,
        })
        .collect();
        let terminal_constant = next::<_, Coordinate<P::Challenge>>(&mut seq)?.0;
        let terminal_values = next::<_, [Coordinate<P::Challenge>; 2]>(&mut seq)?.map(|v| v.0);
        let (max, depth) = opening_bounds(params, 0).map_err(A::Error::custom)?;
        let (rows, proof) = seeded(
            &mut seq,
            OpeningSeed {
                values: Sequence {
                    min: 1,
                    max,
                    element: |_| fields::<P::Base>(M, M),
                },
                depth,
            },
        )?;
        // Validated parameters bound the layer index to 1..ell here. Precompute
        // all geometry with checked arithmetic before visiting the suffix.
        let bounds = (1..params.rounds())
            .map(|j| opening_bounds(params, j))
            .collect::<Result<Vec<_>, _>>()
            .map_err(A::Error::custom)?;
        let scalar_openings = seeded(
            &mut seq,
            Sequence {
                min: bounds.len(),
                max: bounds.len(),
                element: |j: usize| OpeningSeed {
                    values: fields::<P::Challenge>(1, bounds[j].0),
                    depth: bounds[j].1,
                },
            },
        )?
        .into_iter()
        .map(|(values, proof)| ScalarOpening { values, proof })
        .collect();
        Ok(BrakeProof {
            block_values,
            rounds,
            terminal_constant,
            terminal_values,
            initial_opening: MatrixOpening { rows, proof },
            scalar_openings,
        })
    }
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
