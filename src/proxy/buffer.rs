/// Blindly segments a raw byte buffer into smaller chunks of a specified size.
///
/// This function operates strictly at the TCP layer, ignoring any application-layer
/// structure (like HTTP or TLS headers). It is primarily used to fragment plaintext
/// packets to evade Deep Packet Inspection (DPI) systems that match specific byte strings.
///
/// # Arguments
///
/// * `buffer` - A slice of the raw bytes to be fragmented.
/// * `chunk_size` - The maximum size (in bytes) of each resulting chunk.
///
/// # Returns
///
/// A vector containing the fragmented byte vectors.
pub fn blind_chunk_buffer(buffer: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    if buffer.is_empty() {
        return Vec::new();
    }
    if chunk_size == 0 {
        return vec![buffer.to_vec()];
    }
    buffer
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Fragments a single TLS record into multiple, structurally valid TLS records.
///
/// Unlike blind chunking, this function respects the TLS application layer. It extracts
/// the 5-byte TLS header, splits the payload (such as a ClientHello/SNI) into smaller chunks,
/// and re-wraps each chunk with a valid TLS header containing the new, smaller length.
/// This prevents destination servers from dropping the connection due to malformed packets.
///
/// # Arguments
///
/// * `buffer` - A slice representing a single, complete TLS record.
/// * `chunk_size` - The maximum size (in bytes) of the *payload* in each new fragment.
///
/// # Returns
///
/// A vector of newly constructed, valid TLS records. Each record contains a portion of the original payload, properly encapsulated with a TLS header.
pub fn fragment_tls_record(buffer: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    // If the buffer is completely empty, return an empty list of chunks
    if buffer.is_empty() {
        return Vec::new();
    }

    // A TLS record must have at least a 5-byte header:
    // [0]    : Content Type (22 = Handshake)
    // [1..2] : TLS Version
    // [3..4] : Length of the record
    if chunk_size == 0 || buffer.len() <= 5 {
        return vec![buffer.to_vec()];
    }

    let header = &buffer[0..3]; // Content Type and Version
    let payload = &buffer[5..]; // The actual SNI payload data

    payload
        .chunks(chunk_size)
        .map(|chunk| {
            let length = chunk.len() as u16;

            // Construct the new fragmented TLS record
            let mut new_record = Vec::with_capacity(5 + chunk.len());
            new_record.extend_from_slice(header);
            new_record.extend_from_slice(&length.to_be_bytes());
            new_record.extend_from_slice(chunk);
            new_record
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- BLIND CHUNKING TESTS ---

    #[test]
    fn test_blind_chunking_standard() {
        let buffer = vec![1, 2, 3, 4, 5, 6, 7];
        let chunks = blind_chunk_buffer(&buffer, 3);
        assert_eq!(chunks, vec![vec![1, 2, 3], vec![4, 5, 6], vec![7]]);
    }

    #[test]
    fn test_blind_chunking_exact_multiple() {
        let buffer = vec![1, 2, 3, 4, 5, 6];
        let chunks = blind_chunk_buffer(&buffer, 3);
        assert_eq!(chunks, vec![vec![1, 2, 3], vec![4, 5, 6]]);
    }

    #[test]
    fn test_blind_chunking_empty_buffer() {
        let buffer: Vec<u8> = vec![];
        let chunks = blind_chunk_buffer(&buffer, 3);
        assert_eq!(chunks.len(), 0);
    }

    // --- TLS FRAGMENTATION TESTS ---

    #[test]
    fn test_tls_empty_buffer() {
        let buffer: Vec<u8> = vec![];
        let chunks = fragment_tls_record(&buffer, 3);
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn test_tls_record_too_small() {
        // Only 3 bytes (smaller than the required 5-byte header)
        let buffer = vec![22, 3, 3];
        let chunks = fragment_tls_record(&buffer, 10);
        assert_eq!(chunks, vec![buffer]);
    }

    #[test]
    fn test_strict_tls_record_fragmentation() {
        let mut buffer = vec![22, 3, 3, 0, 4];
        buffer.extend_from_slice(&[10, 20, 30, 40]);
        let chunks = fragment_tls_record(&buffer, 2);
        assert_eq!(chunks[0], vec![22, 3, 3, 0, 2, 10, 20]);
        assert_eq!(chunks[1], vec![22, 3, 3, 0, 2, 30, 40]);
    }

    #[test]
    fn test_tls_record_with_remainder() {
        // A 5-byte header indicating a 5-byte payload
        let mut buffer = vec![22, 3, 3, 0, 5];
        buffer.extend_from_slice(&[10, 20, 30, 40, 50]);

        let chunks = fragment_tls_record(&buffer, 2);

        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], vec![22, 3, 3, 0, 2, 10, 20]);
        assert_eq!(chunks[1], vec![22, 3, 3, 0, 2, 30, 40]);
        // The remainder chunk should dynamically calculate a length of 1
        assert_eq!(chunks[2], vec![22, 3, 3, 0, 1, 50]);
    }

    #[test]
    fn test_tls_chunk_size_larger_than_payload() {
        let mut buffer = vec![22, 3, 3, 0, 4];
        buffer.extend_from_slice(&[10, 20, 30, 40]);

        // Requesting a chunk size of 100, which easily fits the 4-byte payload
        let chunks = fragment_tls_record(&buffer, 100);

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], buffer); // Should wrap the original intact
    }

    // --- ZERO CHUNK SIZE TESTS ---

    #[test]
    fn test_zero_chunk_size_safety() {
        let blind_buffer = vec![1, 2, 3];
        let blind_chunks = blind_chunk_buffer(&blind_buffer, 0);
        // Should safely return the intact buffer instead of panicking
        assert_eq!(blind_chunks, vec![blind_buffer.clone()]);

        let mut tls_buffer = vec![22, 3, 3, 0, 4];
        tls_buffer.extend_from_slice(&[10, 20, 30, 40]);
        let tls_chunks = fragment_tls_record(&tls_buffer, 0);
        // Should safely return the intact TLS record instead of panicking
        assert_eq!(tls_chunks, vec![tls_buffer.clone()]);
    }
}
