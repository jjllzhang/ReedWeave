use super::*;

#[test]
fn binding_lists_are_bounded_canonical_and_require_both_coordinates() {
    let binding = Binding::new("3,0-2,2", 0).unwrap();
    assert_eq!(binding.cpu_list(), "0,1,2,3");
    assert_eq!(binding.node(), 0);
    for text in ["", "-1", "1,,2", "3-1", "1024", "1-999999999", "1..3"] {
        assert!(Binding::new(text, 0).is_err(), "{text}");
    }
    assert!(Binding::new("0", 1024).is_err());
    assert!(binding.validate(5).is_err());
    assert!(Measurement::new(0, None, None).is_err());
    assert!(Measurement::new(4, Some("0"), None).is_err());
    assert!(Measurement::new(4, None, Some(0)).is_err());
}

#[test]
fn verification_executes_one_warmup_and_every_timed_call() {
    let measurement = Measurement::new(7, None, None).unwrap();
    let mut calls = 0;
    let seconds = measurement
        .time_verification(|| {
            calls += 1;
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(calls, 8);
    assert!(seconds.is_finite() && seconds >= 0.0);
    // B=1 still means a warmup plus one timed call, not the old cold model.
    let mut calls = 0;
    Measurement::new(1, None, None)
        .unwrap()
        .time_verification(|| {
            calls += 1;
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(calls, 2);
}

#[test]
fn failed_warmup_or_any_batch_member_aborts_measurement() {
    let measurement = Measurement::new(7, None, None).unwrap();
    for failure in [1, 2, 5, 8] {
        let mut calls = 0;
        assert_eq!(
            measurement.time_verification(|| {
                calls += 1;
                if calls == failure {
                    Err("invalid proof")
                } else {
                    Ok(())
                }
            }),
            Err("invalid proof")
        );
        assert_eq!(calls, failure);
    }
}

#[test]
fn measurement_settings_remain_available_for_logging() {
    let measurement = Measurement::new(32, Some("0-3"), Some(0)).unwrap();
    assert_eq!(
        measurement.campaign(42).unwrap(),
        format!(
            "timing_model={TIMING_MODEL}\nverify_repetitions=32\nverify_warmups=1\nseed=42\ncpu_list=0,1,2,3\nmemory_policy=bind\nnuma_node=0\n"
        )
    );
}
