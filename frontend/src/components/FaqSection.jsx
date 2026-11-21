import React, { useState } from "react";
import { motion } from "framer-motion";
import { ChevronDown, ShieldCheck, Clock, Link2, Image, Lock, MessageCircle, ArrowRight } from "lucide-react";

const faqs = [
  {
    q: "What can I scan?",
    a: "Choose Text, SMS, Emails, URLs, Script, Images, or Chat. Each scan returns the fields supported by that input, including a verdict, confidence score, explanation, and structured red flags when present.",
  },
  {
    q: "What does the confidence score mean?",
    a: "It is the model's estimate for the displayed verdict, not a guarantee of safety or fraud. Review the explanation and red flags, and verify unexpected requests through a known, official channel.",
  },
  {
    q: "How is my submitted content handled?",
    a: "Content is sent to the configured Scam Shield backend and may be processed by its configured model provider. Batch results are held in memory; allowlist entries and false-positive feedback are stored in the backend's local SQLite database. Do not submit sensitive content unless your deployment's data policy permits it.",
  },
  {
    q: "What should I do with a suspicious result?",
    a: "Do not click links, send money, or share passwords or one-time codes. Contact the organization through a number or website you already trust. A benign verdict is not proof that a message is safe.",
  },
  {
    q: "Can I integrate the scanner with another application?",
    a: "Yes. The backend exposes HTTP detection endpoints; see Docs for request and response shapes. The frontend and Batch Scan use those same detection services.",
  },
  {
    q: "How does Batch Scan work?",
    a: "Upload a CSV or TXT file to scan a bounded set of messages and URLs. Export results, manage the local allowlist, or record false-positive feedback for review.",
  },
];

const features = [
  {
    icon: <MessageCircle className="h-5 w-5" />,
    title: "Message cues",
    description: "Review urgency, payment, credential, and impersonation cues in submitted text."
  },
  {
    icon: <Clock className="h-5 w-5" />,
    title: "Link inspection",
    description: "Lookalike domains, short links, and suspicious URL patterns are surfaced for review."
  },
  {
    icon: <ShieldCheck className="h-5 w-5" />,
    title: "Multiple formats",
    description: "Inspect messages, email, scripts, images, URLs, and chat from one workbench."
  },
  {
    icon: <Lock className="h-5 w-5" />,
    title: "Local review tools",
    description: "Maintain a local allowlist and submit false-positive feedback for later review."
  },
  {
    icon: <Link2 className="h-5 w-5" />,
    title: "Evidence details",
    description: "Review confidence, red flags, explanations, and the raw response."
  },
  {
    icon: <Image className="h-5 w-5" />,
    title: "Image review",
    description: "Extract readable image text and inspect the resulting scan verdict."
  }
];

function FeaturesSection() {
  return (
    <section className="mt-16 border-t border-orange-100 pt-10">
      <div className="mx-auto max-w-3xl px-4">
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.22 }}
          viewport={{ once: true }}
          className="mb-8 text-center"
        >
          <h2 className="mb-3 text-xl font-semibold text-slate-900 sm:text-2xl">
            What the scanner checks
          </h2>
          <p className="mx-auto max-w-2xl px-4 text-base leading-relaxed text-slate-600">
            Review practical signals across the message formats people use every day.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((feature, index) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 8 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.04, duration: 0.22 }}
              viewport={{ once: true }}
              className="h-full rounded-xl border border-slate-200 bg-white p-4 transition-colors hover:border-orange-200"
            >
                <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg bg-orange-100 text-orange-600">
                  {feature.icon}
                </div>
                <h3 className="mb-2 text-base font-semibold text-slate-900">{feature.title}</h3>
                <p className="text-sm leading-relaxed text-slate-600">{feature.description}</p>
            </motion.div>
          ))}
        </div>

        <motion.div
          initial={{ opacity: 0, y: 8 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.24, duration: 0.22 }}
          viewport={{ once: true }}
          className="mt-8 text-center"
        >
          <div className="inline-flex items-center gap-2 rounded-full bg-orange-50 px-4 py-2 text-sm font-medium text-orange-800">
            <ShieldCheck className="h-4 w-4" />
            <span>Verdict · Confidence · Evidence</span>
          </div>
        </motion.div>
      </div>
    </section>
  );
}

export default function FaqSection() {
  const [openIndex, setOpenIndex] = useState(null);

  return (
    <>
      <FeaturesSection />
      
      <section className="mt-16 mb-12">
        <div className="mx-auto max-w-3xl px-4">
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.22 }}
            viewport={{ once: true }}
            className="mb-8 text-center"
          >
            <h2 className="mb-3 text-xl font-semibold text-slate-900 sm:text-2xl">
              Frequently asked <span className="text-orange-500">questions</span>
            </h2>
            <p className="px-4 text-base leading-relaxed text-slate-600">
              How to use scan results and review suspicious content safely.
            </p>
          </motion.div>

          <div className="space-y-4">
            {faqs.map((item, index) => {
              const isOpen = openIndex === index;
              return (
                <motion.div
                  key={item.q}
                  initial={{ opacity: 0, y: 8 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.04, duration: 0.22 }}
                  viewport={{ once: true }}
                >
                  <button
                    type="button"
                    onClick={() => setOpenIndex(isOpen ? null : index)}
                    className="w-full text-left group"
                  >
                    <div className="rounded-xl border border-slate-200 bg-white p-4 transition-colors hover:border-orange-200 sm:p-5">
                      <div className="flex items-center justify-between gap-2 sm:gap-4">
                        <p className="pr-2 text-sm font-semibold text-slate-900 sm:text-base">{item.q}</p>
                        <motion.div
                          animate={{ rotate: isOpen ? 180 : 0 }}
                          transition={{ duration: 0.2 }}
                          className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full bg-orange-100 text-orange-600 transition-colors group-hover:bg-orange-200"
                        >
                          <ChevronDown className="h-3 w-3 sm:h-4 sm:w-4" />
                        </motion.div>
                      </div>
                      
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ 
                          height: isOpen ? "auto" : 0, 
                          opacity: isOpen ? 1 : 0 
                        }}
                        transition={{ duration: 0.3, ease: "easeInOut" }}
                        className="overflow-hidden"
                      >
                        <p className="mt-3 border-t border-slate-100 pt-3 text-sm leading-relaxed text-slate-600 sm:mt-4 sm:pt-4">
                          {item.a}
                        </p>
                      </motion.div>
                    </div>
                  </button>
                </motion.div>
              );
            })}
          </div>

          <motion.div
            initial={{ opacity: 0, y: 8 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.24, duration: 0.22 }}
            viewport={{ once: true }}
            className="mt-8 text-center"
          >
            <p className="mb-4 text-sm text-slate-600">Need scan or API details?</p>
            <a
              href="/docs"
              className="inline-flex items-center gap-2 rounded-lg bg-orange-500 px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-orange-600"
            >
              Visit Documentation
              <ArrowRight className="h-3 w-3 sm:h-4 sm:w-4" />
            </a>
          </motion.div>
        </div>
      </section>
    </>
  );
}
