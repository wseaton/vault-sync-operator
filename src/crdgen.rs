use kube::CustomResourceExt;

mod crd;
fn main() {
    print!("{}", serde_yaml::to_string(&crd::VaultSecret::crd()).unwrap())
}