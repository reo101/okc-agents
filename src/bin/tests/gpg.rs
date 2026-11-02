use super::*;

#[test]
fn argument_validation_and_forwarding() {
    for arguments in [
        vec!["--list-secret-keys"],
        vec!["--export-secret-keys"],
        vec!["--list-keys", "--with-colons"],
        vec!["--gen-key"],
        vec!["--delete-keys"],
        vec!["--recv-keys"],
        vec!["--decrypt", "--passphrase", "secret"],
        vec!["--encrypt", "--hidden-recipient", "user@example.com"],
        vec!["--sign"],
        vec!["--decrypt", "--export"],
        vec!["--export", "--metadata"],
        vec!["--decrypt", "--status-fd", "1"],
        vec!["--decrypt", "--batch"],
        vec!["--encrypt", "--bzip2-compress-level", "10"],
        vec!["--export", "--backup"],
    ] {
        let mut command = vec!["okc-gpg"];
        command.extend(arguments);
        let args = GpgArgs::try_parse_from(command).unwrap();
        assert!(validate_args(&args).is_err(), "Accepted {args:?}");
    }
    let args = GpgArgs::try_parse_from([
        "okc-gpg",
        "--detach-sign",
        "--status-fd",
        "2",
        "-u",
        "user@example.com",
        "--",
        "-input",
    ])
    .unwrap();
    validate_args(&args).unwrap();
    assert_eq!(
        reconstruct_args(&args),
        [
            "--detach-sign",
            "--status-fd",
            "2",
            "--local-user",
            "user@example.com",
            "--",
            "-input"
        ]
    );
    let git_args =
        GpgArgs::try_parse_from(["okc-gpg", "--status-fd=2", "-bsau", "user@example.com"]).unwrap();
    validate_args(&git_args).unwrap();
    let args =
        GpgArgs::try_parse_from(["okc-gpg", "--backup", "--backup-secret", "0123456789ABCDEF"])
            .unwrap();
    validate_args(&args).unwrap();
    assert_eq!(
        reconstruct_args(&args),
        ["--backup", "--backup-secret", "--", "0123456789ABCDEF"]
    );
    for args in [
        vec![
            "--encrypt",
            "-r",
            "first@example.com",
            "--encrypt-to",
            "0123456789ABCDEF",
        ],
        vec!["--sign", "--encrypt"],
        vec!["--decrypt", "--verify"],
    ] {
        let mut command = vec!["okc-gpg"];
        command.extend(args);
        validate_args(&GpgArgs::try_parse_from(command).unwrap()).unwrap();
    }
}

#[tokio::test]
async fn framing_round_trip_and_truncation() {
    let data: Vec<u8> = (0..=255).cycle().take(150000).collect();
    let mut encoded = Vec::new();
    copy_to_length_prefixed(&mut data.as_slice(), &mut encoded)
        .await
        .unwrap();
    let mut decoded = Vec::new();
    copy_from_length_prefixed(&mut encoded.as_slice(), &mut decoded)
        .await
        .unwrap();
    assert_eq!(decoded, data);
    for input in [&[0u8][..], &[0, 5, 1][..], &[0, 1, 255][..]] {
        assert!(
            copy_from_length_prefixed(&mut &input[..], &mut Vec::new())
                .await
                .is_err()
        );
    }
    assert!(
        read_length_prefixed_str(&mut &[0, 1, 255][..])
            .await
            .is_err()
    );
    assert!(ConnectionType::try_from(7).is_err());
}

async fn control_stream(port: u16) -> TcpStream {
    let mut control = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    control.write_u8(0).await.unwrap();
    control
}

#[tokio::test]
async fn control_only_actions_and_provider_failure() {
    for status in [0, 1] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(serve_gpg_connections(listener, Vec::new(), "-".to_string()));
        let mut control = control_stream(port).await;
        control.write_all(&[0, 0, status]).await.unwrap();
        let result = time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.is_ok(), status == 0);
    }
}

#[tokio::test]
async fn output_only_and_repeated_input_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let directory = tempfile::tempdir().unwrap();
    let input_path = directory.path().join("message");
    let output_path = directory.path().join("output");
    let server = tokio::spawn(serve_gpg_connections(
        listener,
        vec![input_path.to_str().unwrap().to_string()],
        output_path.to_str().unwrap().to_string(),
    ));
    let mut control = control_stream(port).await;
    let data: Vec<u8> = (0..=255).collect();
    tokio::fs::write(&input_path, &data).await.unwrap();
    for _ in 0..2 {
        let mut input = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        input.write_u8(1).await.unwrap();
        let path = input_path.to_str().unwrap().as_bytes();
        input.write_u16(path.len() as u16).await.unwrap();
        input.write_all(path).await.unwrap();
        let mut decoded = Vec::new();
        copy_from_length_prefixed(&mut input, &mut decoded)
            .await
            .unwrap();
        assert_eq!(decoded, data);
    }
    let mut output = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    output.write_u8(2).await.unwrap();
    let path = output_path.to_str().unwrap().as_bytes();
    output.write_u16(path.len() as u16).await.unwrap();
    output.write_all(path).await.unwrap();
    copy_to_length_prefixed(&mut data.as_slice(), &mut output)
        .await
        .unwrap();
    output.shutdown().await.unwrap();
    control.write_all(&[0, 0, 0]).await.unwrap();
    time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(tokio::fs::read(output_path).await.unwrap(), data);
}

#[tokio::test]
async fn stream_error_terminates_control_wait() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_gpg_connections(
        listener,
        vec!["/path/that/does/not/exist".to_string()],
        "-".to_string(),
    ));
    let mut control = control_stream(port).await;
    let mut input = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    input.write_u8(1).await.unwrap();
    let path = b"/path/that/does/not/exist";
    input.write_u16(path.len() as u16).await.unwrap();
    input.write_all(path).await.unwrap();
    assert!(
        time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(
        time::timeout(Duration::from_secs(2), control.read_u8())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn callbacks_cannot_select_unrequested_files() {
    for kind in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let protected = directory.path().join("protected");
        tokio::fs::write(&protected, b"private contents")
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(serve_gpg_connections(listener, Vec::new(), "-".to_string()));
        let _control = control_stream(port).await;
        let mut connection = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        connection.write_u8(kind).await.unwrap();
        let path = protected.to_str().unwrap().as_bytes();
        connection.write_u16(path.len() as u16).await.unwrap();
        connection.write_all(path).await.unwrap();
        assert!(
            time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(
            tokio::fs::read(&protected).await.unwrap(),
            b"private contents"
        );
        assert!(
            connection.read_u8().await.is_err(),
            "Unrequested input data was exposed"
        );
    }
}
