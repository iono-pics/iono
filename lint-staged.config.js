export default {
	"server/**/*.rs": () => "cargo fmt --manifest-path server/Cargo.toml --all",
};
