(function() {var type_impls = {
"vt3":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-Collection%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/vt3/public_api/model.rs.html#3\">source</a><a href=\"#impl-Debug-for-Collection%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"vt3/public_api/model/struct.Collection.html\" title=\"struct vt3::public_api::model::Collection\">Collection</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/vt3/public_api/model.rs.html#3\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.75.0/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.75.0/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/1.75.0/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.75.0/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","vt3::public_api::votes::model::Votes"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-Collection%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/vt3/public_api/model.rs.html#3\">source</a><a href=\"#impl-Deserialize%3C'de%3E-for-Collection%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de, T: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"vt3/public_api/model/struct.Collection.html\" title=\"struct vt3::public_api::model::Collection\">Collection</a>&lt;T&gt;<span class=\"where fmt-newline\">where\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/1.75.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"struct\" href=\"vt3/public_api/model/struct.Data.html\" title=\"struct vt3::public_api::model::Data\">Data</a>&lt;T&gt;&gt;: <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/vt3/public_api/model.rs.html#3\">source</a><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;__D&gt;(__deserializer: __D) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.75.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, __D::<a class=\"associatedtype\" href=\"serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<span class=\"where fmt-newline\">where\n    __D: <a class=\"trait\" href=\"serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</span></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","vt3::public_api::votes::model::Votes"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-Collection%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/vt3/public_api/model.rs.html#3\">source</a><a href=\"#impl-Serialize-for-Collection%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"vt3/public_api/model/struct.Collection.html\" title=\"struct vt3::public_api::model::Collection\">Collection</a>&lt;T&gt;<span class=\"where fmt-newline\">where\n    T: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/vt3/public_api/model.rs.html#3\">source</a><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;__S&gt;(&amp;self, __serializer: __S) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.75.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;__S::<a class=\"associatedtype\" href=\"serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, __S::<a class=\"associatedtype\" href=\"serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<span class=\"where fmt-newline\">where\n    __S: <a class=\"trait\" href=\"serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</span></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","vt3::public_api::votes::model::Votes"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()