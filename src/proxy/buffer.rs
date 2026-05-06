/// The main entry point for splitting network packets to bypass DPI.
/// A blind TCP segmentation tool.
pub fn buffer_to_chunks(buffer: &Vec<u8>, chunk_size: usize) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    let mut i = 0;

    // Blindly chunk the stream for TCP transmission
    while i < buffer.len() {
        let end = std::cmp::min(i + chunk_size, buffer.len());
        result.push(buffer[i..end].to_vec());
        i += chunk_size;
    }

    result
}

/// Parses the initial ClientHello packet and breaks it down into
/// multiple, structurally valid TLS records that share the same handshake.
pub fn tls_record_fragmentation(buffer: &Vec<u8>, chunk_size: usize) -> Vec<Vec<u8>> {
    // If the buffer is completely empty, return an empty list of chunks
    if buffer.is_empty() {
        return Vec::new();
    }

    // A TLS record must have at least a 5-byte header:
    // [0]    : Content Type (22 = Handshake)
    // [1..2] : TLS Version
    // [3..4] : Length of the record
    if buffer.len() <= 5 {
        return vec![buffer.to_vec()];
    }

    let mut result = Vec::new();

    let header = &buffer[0..3]; // Content Type and Version
    let full_record = &buffer[5..]; // The actual SNI payload data

    let mut i = 0;
    while i < full_record.len() {
        let end = std::cmp::min(i + chunk_size, full_record.len());
        let record_chunk = &full_record[i..end];
        let record_length = record_chunk.len() as u16;

        // Construct the new fragmented TLS record
        let mut new_record = Vec::with_capacity(5 + record_chunk.len());
        new_record.extend_from_slice(header);
        new_record.extend_from_slice(&record_length.to_be_bytes());
        new_record.extend_from_slice(record_chunk);

        result.push(new_record);
        i += chunk_size;
    }

    result
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_chunking_standard() {
        let buffer = vec![1, 2, 3, 4, 5, 6, 7];
        let chunks = buffer_to_chunks(&buffer, 3);
        // Should split into [1,2,3], [4,5,6], and the remainder [7]
        assert_eq!(chunks, vec![vec![1, 2, 3], vec![4, 5, 6], vec![7]]);
    }

    #[test]
    fn test_blind_chunking_exact_multiple() {
        let buffer = vec![1, 2, 3, 4, 5, 6];
        let chunks = buffer_to_chunks(&buffer, 3);
        // Should perfectly split into two chunks with no remainder
        assert_eq!(chunks, vec![vec![1, 2, 3], vec![4, 5, 6]]);
    }

    #[test]
    fn test_empty_buffer() {
        let buffer: Vec<u8> = vec![];
        let chunks = tls_record_fragmentation(&buffer, 3);
        // Should safely return nothing without panicking
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn test_tls_record_too_small() {
        // A packet smaller than the 5-byte TLS header
        let buffer = vec![22, 3, 3];
        let chunks = tls_record_fragmentation(&buffer, 10);
        // It cannot parse a TLS header, so it should just return the original chunk intact
        assert_eq!(chunks, vec![buffer]);
    }

    #[test]
    fn test_strict_tls_record_fragmentation() {
        // A mock TLS packet.
        // First 5 bytes are the header: [Type (22=Handshake), Version_Major, Version_Minor, Length_High, Length_Low]
        // Following bytes are the "SNI payload" data.
        let mut buffer = vec![22, 3, 3, 0, 4]; // Header indicating 4 bytes of payload
        buffer.extend_from_slice(&[10, 20, 30, 40]); // The 4 bytes of mock payload

        // We want to fragment this into chunk sizes of 2 bytes for the payload
        let chunks = tls_record_fragmentation(&buffer, 2);

        // We expect it to construct TWO completely valid TLS records!
        // Record 1: Header + Length of 2 + [10, 20]
        assert_eq!(chunks[0], vec![22, 3, 3, 0, 2, 10, 20]);

        // Record 2: Header + Length of 2 + [30, 40]
        assert_eq!(chunks[1], vec![22, 3, 3, 0, 2, 30, 40]);
    }
}
