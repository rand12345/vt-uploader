(function() {var implementors = {
"ansi_term":[["impl&lt;'a, S: 'a + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/alloc/borrow/trait.ToOwned.html\" title=\"trait alloc::borrow::ToOwned\">ToOwned</a> + ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"ansi_term/struct.ANSIGenericString.html\" title=\"struct ansi_term::ANSIGenericString\">ANSIGenericString</a>&lt;'a, S&gt;<span class=\"where fmt-newline\">where\n    &lt;S as <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/alloc/borrow/trait.ToOwned.html\" title=\"trait alloc::borrow::ToOwned\">ToOwned</a>&gt;::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.75.0/alloc/borrow/trait.ToOwned.html#associatedtype.Owned\" title=\"type alloc::borrow::ToOwned::Owned\">Owned</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>,</span>"]],
"bytes":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"bytes/struct.Bytes.html\" title=\"struct bytes::Bytes\">Bytes</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"bytes/struct.BytesMut.html\" title=\"struct bytes::BytesMut\">BytesMut</a>"]],
"core_foundation":[["impl&lt;'a, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"core_foundation/base/struct.ItemMutRef.html\" title=\"struct core_foundation::base::ItemMutRef\">ItemMutRef</a>&lt;'a, T&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"core_foundation/data/struct.CFData.html\" title=\"struct core_foundation::data::CFData\">CFData</a>"],["impl&lt;'a, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"core_foundation/base/struct.ItemRef.html\" title=\"struct core_foundation::base::ItemRef\">ItemRef</a>&lt;'a, T&gt;"]],
"futures_task":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"futures_task/struct.WakerRef.html\" title=\"struct futures_task::WakerRef\">WakerRef</a>&lt;'_&gt;"]],
"futures_util":[["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>, U: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"futures_util/lock/struct.MappedMutexGuard.html\" title=\"struct futures_util::lock::MappedMutexGuard\">MappedMutexGuard</a>&lt;'_, T, U&gt;"],["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"futures_util/lock/struct.MutexGuard.html\" title=\"struct futures_util::lock::MutexGuard\">MutexGuard</a>&lt;'_, T&gt;"],["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"futures_util/lock/struct.OwnedMutexGuard.html\" title=\"struct futures_util::lock::OwnedMutexGuard\">OwnedMutexGuard</a>&lt;T&gt;"]],
"once_cell":[["impl&lt;T, F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/function/trait.FnOnce.html\" title=\"trait core::ops::function::FnOnce\">FnOnce</a>() -&gt; T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"once_cell/unsync/struct.Lazy.html\" title=\"struct once_cell::unsync::Lazy\">Lazy</a>&lt;T, F&gt;"],["impl&lt;T, F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/function/trait.FnOnce.html\" title=\"trait core::ops::function::FnOnce\">FnOnce</a>() -&gt; T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"once_cell/sync/struct.Lazy.html\" title=\"struct once_cell::sync::Lazy\">Lazy</a>&lt;T, F&gt;"]],
"rustls_pki_types":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"rustls_pki_types/struct.CertificateSigningRequestDer.html\" title=\"struct rustls_pki_types::CertificateSigningRequestDer\">CertificateSigningRequestDer</a>&lt;'_&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"rustls_pki_types/struct.Der.html\" title=\"struct rustls_pki_types::Der\">Der</a>&lt;'_&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"rustls_pki_types/struct.CertificateRevocationListDer.html\" title=\"struct rustls_pki_types::CertificateRevocationListDer\">CertificateRevocationListDer</a>&lt;'_&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"rustls_pki_types/struct.AlgorithmIdentifier.html\" title=\"struct rustls_pki_types::AlgorithmIdentifier\">AlgorithmIdentifier</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"rustls_pki_types/struct.CertificateDer.html\" title=\"struct rustls_pki_types::CertificateDer\">CertificateDer</a>&lt;'_&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"rustls_pki_types/struct.EchConfigListBytes.html\" title=\"struct rustls_pki_types::EchConfigListBytes\">EchConfigListBytes</a>&lt;'_&gt;"]],
"security_framework":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"security_framework/os/macos/passwords/struct.SecKeychainItemPassword.html\" title=\"struct security_framework::os::macos::passwords::SecKeychainItemPassword\">SecKeychainItemPassword</a>"]],
"smallvec":[["impl&lt;A: <a class=\"trait\" href=\"smallvec/trait.Array.html\" title=\"trait smallvec::Array\">Array</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"smallvec/struct.SmallVec.html\" title=\"struct smallvec::SmallVec\">SmallVec</a>&lt;A&gt;"]],
"socket2":[["impl&lt;'s&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"socket2/struct.SockRef.html\" title=\"struct socket2::SockRef\">SockRef</a>&lt;'s&gt;"],["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"socket2/struct.MaybeUninitSlice.html\" title=\"struct socket2::MaybeUninitSlice\">MaybeUninitSlice</a>&lt;'a&gt;"]],
"tempfile":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tempfile/struct.TempPath.html\" title=\"struct tempfile::TempPath\">TempPath</a>"]],
"tinyvec":[["impl&lt;A: <a class=\"trait\" href=\"tinyvec/trait.Array.html\" title=\"trait tinyvec::Array\">Array</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"enum\" href=\"tinyvec/enum.TinyVec.html\" title=\"enum tinyvec::TinyVec\">TinyVec</a>&lt;A&gt;"],["impl&lt;'s, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tinyvec/struct.SliceVec.html\" title=\"struct tinyvec::SliceVec\">SliceVec</a>&lt;'s, T&gt;"],["impl&lt;A: <a class=\"trait\" href=\"tinyvec/trait.Array.html\" title=\"trait tinyvec::Array\">Array</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tinyvec/struct.ArrayVec.html\" title=\"struct tinyvec::ArrayVec\">ArrayVec</a>&lt;A&gt;"]],
"tokio":[["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tokio/sync/struct.RwLockMappedWriteGuard.html\" title=\"struct tokio::sync::RwLockMappedWriteGuard\">RwLockMappedWriteGuard</a>&lt;'_, T&gt;"],["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>, U: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tokio/sync/struct.OwnedMappedMutexGuard.html\" title=\"struct tokio::sync::OwnedMappedMutexGuard\">OwnedMappedMutexGuard</a>&lt;T, U&gt;"],["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tokio/sync/struct.MutexGuard.html\" title=\"struct tokio::sync::MutexGuard\">MutexGuard</a>&lt;'_, T&gt;"],["impl&lt;'a, T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tokio/sync/struct.MappedMutexGuard.html\" title=\"struct tokio::sync::MappedMutexGuard\">MappedMutexGuard</a>&lt;'a, T&gt;"],["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>, U: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tokio/sync/struct.OwnedRwLockMappedWriteGuard.html\" title=\"struct tokio::sync::OwnedRwLockMappedWriteGuard\">OwnedRwLockMappedWriteGuard</a>&lt;T, U&gt;"],["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>, U: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tokio/sync/struct.OwnedRwLockReadGuard.html\" title=\"struct tokio::sync::OwnedRwLockReadGuard\">OwnedRwLockReadGuard</a>&lt;T, U&gt;"],["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tokio/sync/struct.RwLockReadGuard.html\" title=\"struct tokio::sync::RwLockReadGuard\">RwLockReadGuard</a>&lt;'_, T&gt;"],["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tokio/sync/struct.OwnedRwLockWriteGuard.html\" title=\"struct tokio::sync::OwnedRwLockWriteGuard\">OwnedRwLockWriteGuard</a>&lt;T&gt;"],["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tokio/sync/struct.RwLockWriteGuard.html\" title=\"struct tokio::sync::RwLockWriteGuard\">RwLockWriteGuard</a>&lt;'_, T&gt;"],["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tokio/sync/struct.OwnedMutexGuard.html\" title=\"struct tokio::sync::OwnedMutexGuard\">OwnedMutexGuard</a>&lt;T&gt;"],["impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tokio/sync/watch/struct.Ref.html\" title=\"struct tokio::sync::watch::Ref\">Ref</a>&lt;'_, T&gt;"]],
"tracing":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"tracing/span/struct.EnteredSpan.html\" title=\"struct tracing::span::EnteredSpan\">EnteredSpan</a>"]],
"try_lock":[["impl&lt;'a, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"try_lock/struct.Locked.html\" title=\"struct try_lock::Locked\">Locked</a>&lt;'a, T&gt;"]],
"unicase":[["impl&lt;S&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"unicase/struct.UniCase.html\" title=\"struct unicase::UniCase\">UniCase</a>&lt;S&gt;"],["impl&lt;S&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"unicase/struct.Ascii.html\" title=\"struct unicase::Ascii\">Ascii</a>&lt;S&gt;"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()