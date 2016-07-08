# Microlibraries

Microlibraries are specially packaged units of source code. They have some special properties which seem
like good practice to me at this particular moment but may rub some other people the wrong way.

I first started toying with this approach when I was working on the [TweetPepper project](https://github.com/buttermilk-crypto/tweetPepper). I was focused there on producing a library which had no dependencies. (I settled for one.) 

But in working to reduce dependencies I discovered I needed a bit here and a piece there from other open
source projects.

I found that for some cases I wanted code which would ordinarily have required bringing in a large jar file such as with Bouncy Castle, or multiple dependent libraries, when in reality I did not need all of that code, just the one bit of functionality I needed. 

I have no doubt there are ways to generate an extract of a jar based on profiling or other detection of what is used. But, tools like that are out of my reach. What I did was just manual extraction based on the source code. 

I found in that process I was continually reworking away certain idioms. For example, certain interfaces exist only to allow code to span packages. I did not need it. I discovered or rediscovered for myself the package protected class was my friend, and the idea that more than one Java(tm) class can exist in a source file was something of a revelation to me. 

For Java(tm) only one public class can exist in a source file - but why would you choose to have more than one?

Typically you would not. In the general case we would like to have code be reused which means making classes public. If you have a package with some classes you want to call methods from some other package. But, what I found is this often actually is a glue to allow a library to expand, possibly beyond the reasonable size and scope of what it should reasonably do. It might actually be better, I argued, for those different packages to be discrete projects. 

In my case intuitively I wanted to provide something different from a large library. A very strong level of encapsulation can only be provided by a single package or even a single source file. Basically I want nothing to be visible outside the package except a service method or a set of factory methods which I present.

This is in part because I am mainly _not_ the author of the code for these packages, someone else is, and so I was able to see the code in light of being packaged rather than written. You can think of it as an outcome of Github - my objective is not to reuse the code in the standard way but actually to make it encapsulated to the point of not being extensible at all. It is like reducing an entire library down to one method.

What is achieved? Well, there is an old problem with open source projects - if you start changing a few methods in a large open source project, you end up owning the whole project in terms of support. For ever after you have to maintain your changes in the light of upgrades and divergent code from the project. If it is a big project, the task can be daunting. 

But, imagine if the library itself is quite small and does something relatively easy to encapsulate into a simple method or a few functions. It is true, there is still the cost of repackaging the new code when it comes out from the vendor, but the encapsulation allows for a much tighter interface and so the cost of maintenance on my own modifications should be much lower. Or at any rate, much easier to digest.

I am still working out the taxonomy of a microlibrary. Microlibraries seem have the following characteristics:

  - One or a small integer number of source files
  - Zero dependencies on other code outside the JDK.
  - A simple service interface such as a single method
  - must be larger than a gist or snippit. There has to be enough to encapsulate
  
Microlibraries may have something to do with [microservices](http://martinfowler.com/articles/microservices.html). I'm not sure what yet, but intrinsically there seems to be a connection. 


