use argon2::vec_from_slices;

#[test]
fn vec_from_slices() {
    let vec_a = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let vec_b = vec![9, 8, 7];
    assert_eq!(
        &vec_from_slices!(&vec_a, &vec_b),
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7]
    );
}
