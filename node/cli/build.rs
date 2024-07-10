fn main() {
	cli::main();
}

mod cli {
	include!("src/cli.rs");

	use substrate_build_script_utils::{generate_cargo_keys, rerun_if_git_head_changed};

	pub fn main() {
		generate_cargo_keys();

		rerun_if_git_head_changed();
	}
}
